"""Automatically remove project-owned firewall blocks after their expiry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event

from ssh_security_app.audit import AuditService
from ssh_security_app.constants import BlockStatus
from ssh_security_app.core.normalization import ensure_utc
from ssh_security_app.db.repositories import BlockRepository
from ssh_security_app.health import HealthMonitor
from ssh_security_app.response.firewall_manager import FirewallError, FirewallManager


@dataclass(frozen=True)
class ExpirationCycleResult:
    examined: int
    expired: int
    failed: int


class ExpirationWorker:
    component_name = "expiration_worker"

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

    def process_once(self, *, limit: int = 100) -> ExpirationCycleResult:
        now = ensure_utc(self.clock())
        candidates = self.blocks.list_expired(at=now, limit=limit)
        expired = 0
        failed = 0
        for block in candidates:
            try:
                exists = self.firewall.rule_exists(block.source_ip)
            except FirewallError as exc:
                self._record_failure(block.block_id, block.source_ip, str(exc))
                failed += 1
                continue

            firewall_message = "exact block rule was already absent"
            if exists:
                operation = self.firewall.delete_block_rule(block.source_ip)
                firewall_message = operation.message
                if not operation.success:
                    self._record_failure(
                        block.block_id,
                        block.source_ip,
                        operation.message,
                    )
                    failed += 1
                    continue

            updated = self.blocks.mark_removed(
                block.block_id,
                status=BlockStatus.EXPIRED,
                removal_method="Automatic",
                removed_at=now,
                firewall_result=firewall_message,
            )
            if not updated:
                self._record_failure(
                    block.block_id,
                    block.source_ip,
                    "block status changed while expiration was being processed",
                )
                failed += 1
                continue
            expired += 1
            self.audit.record(
                component=self.component_name,
                action="automatic_unblock",
                target=block.source_ip,
                result="success",
                details={"block_id": block.block_id, "firewall": firewall_message},
            )

        if failed:
            self.health.degraded(
                self.component_name,
                f"{failed} expired block(s) could not be processed",
                examined=len(candidates),
                expired=expired,
                failed=failed,
            )
        else:
            self.health.healthy(
                self.component_name,
                examined=len(candidates),
                expired=expired,
                failed=0,
            )
        return ExpirationCycleResult(len(candidates), expired, failed)

    def run(self, stop_event: Event, *, interval_seconds: int) -> None:
        if interval_seconds < 1:
            raise ValueError("expiration interval must be positive")
        while not stop_event.is_set():
            self.process_once()
            stop_event.wait(interval_seconds)
        self.health.stopped(self.component_name)

    def _record_failure(self, block_id: str, source_ip: str, message: str) -> None:
        self.blocks.record_error(block_id, error_message=message)
        self.audit.record(
            component=self.component_name,
            action="automatic_unblock",
            target=source_ip,
            result="failure",
            details={"block_id": block_id, "error": message},
        )
