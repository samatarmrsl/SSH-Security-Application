"""Reconcile SQLite block state with the dedicated project firewall chain."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from ssh_security_app.audit import AuditService
from ssh_security_app.constants import BlockStatus
from ssh_security_app.core.normalization import ensure_utc
from ssh_security_app.db.repositories import BlockRepository
from ssh_security_app.health import HealthMonitor
from ssh_security_app.response.firewall_manager import FirewallManager
from ssh_security_app.response.rules import parse_project_rules


@dataclass(frozen=True)
class ReconciliationResult:
    active_consistent: int
    expired_removed: int
    missing_marked_inconsistent: int
    unknown_rules: int
    failed: int


class FirewallReconciler:
    component_name = "firewall_reconciler"

    def __init__(
        self,
        *,
        firewall: FirewallManager,
        blocks: BlockRepository,
        audit: AuditService,
        health: HealthMonitor,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.firewall = firewall
        self.blocks = blocks
        self.audit = audit
        self.health = health
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def reconcile(self, *, limit: int = 10_000) -> ReconciliationResult:
        now = ensure_utc(self.clock())
        operation, lines = self.firewall.list_project_rules()
        if not operation.success:
            self.health.failed(self.component_name, operation.message)
            self.audit.record(
                component=self.component_name,
                action="reconciliation",
                result="failure",
                details={"error": operation.message},
            )
            return ReconciliationResult(0, 0, 0, 0, 1)

        parsed = parse_project_rules(
            lines,
            chain=self.firewall.builder.chain,
            ssh_port=self.firewall.builder.ssh_port,
        )
        remaining = parsed.source_counts
        consistent = 0
        expired = 0
        inconsistent = 0
        failed = 0

        for block in self.blocks.list_active(limit):
            rule_count = remaining.get(block.source_ip, 0)
            if block.expires_at <= now:
                firewall_message = "exact block rule was already absent"
                if rule_count:
                    removal = self.firewall.delete_block_rule(block.source_ip)
                    firewall_message = removal.message
                    if not removal.success:
                        self.blocks.record_error(
                            block.block_id,
                            error_message=removal.message,
                            firewall_result=removal.message,
                        )
                        self._audit_block(
                            block.source_ip, block.block_id, "failure", removal.message
                        )
                        failed += 1
                        continue
                    remaining[block.source_ip] -= 1
                if self.blocks.mark_removed(
                    block.block_id,
                    status=BlockStatus.EXPIRED,
                    removal_method="Reconciliation",
                    removed_at=now,
                    firewall_result=firewall_message,
                ):
                    expired += 1
                    self._audit_block(
                        block.source_ip,
                        block.block_id,
                        "expired",
                        firewall_message,
                    )
                else:
                    failed += 1
                continue

            if rule_count:
                remaining[block.source_ip] -= 1
                consistent += 1
                continue

            message = "active database block has no matching project firewall rule"
            if self.blocks.mark_removed(
                block.block_id,
                status=BlockStatus.INCONSISTENT,
                removal_method="Reconciliation",
                removed_at=now,
                error_message=message,
            ):
                inconsistent += 1
                self._audit_block(block.source_ip, block.block_id, "inconsistent", message)
            else:
                failed += 1

        unknown = len(parsed.unknown_rules) + sum(
            count for count in remaining.values() if count > 0
        )
        for line in parsed.unknown_rules:
            self._audit_unknown(line)
        for source, count in remaining.items():
            for _ in range(max(0, count)):
                self._audit_unknown(f"unowned exact rule for {source}")

        result = ReconciliationResult(
            consistent,
            expired,
            inconsistent,
            unknown,
            failed,
        )
        if failed:
            self.health.failed(
                self.component_name,
                f"{failed} reconciliation action(s) failed",
                **result.__dict__,
            )
        elif inconsistent or unknown:
            self.health.degraded(
                self.component_name,
                "firewall and database state require operator review",
                **result.__dict__,
            )
        else:
            self.health.healthy(self.component_name, **result.__dict__)
        self.audit.record(
            component=self.component_name,
            action="reconciliation_summary",
            result="failure" if failed else "review" if inconsistent or unknown else "success",
            details=result.__dict__,
        )
        return result

    def _audit_block(
        self,
        source_ip: str,
        block_id: str,
        result: str,
        message: str,
    ) -> None:
        self.audit.record(
            component=self.component_name,
            action="reconciliation",
            target=source_ip,
            result=result,
            details={"block_id": block_id, "message": message},
        )

    def _audit_unknown(self, rule: str) -> None:
        self.audit.record(
            component=self.component_name,
            action="unknown_firewall_rule",
            result="review",
            details={"rule": rule, "automatic_deletion": False},
        )
