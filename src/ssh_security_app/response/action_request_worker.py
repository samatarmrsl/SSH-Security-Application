"""SQLite request boundary for dashboard-triggered manual unblocks."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from ssh_security_app.audit import AuditService
from ssh_security_app.constants import ActionRequestStatus, BlockStatus
from ssh_security_app.core.normalization import ensure_utc
from ssh_security_app.db.repositories import ActionRequestRepository, BlockRepository
from ssh_security_app.health import HealthMonitor
from ssh_security_app.models import ActionRequest
from ssh_security_app.response.firewall_manager import FirewallError, FirewallManager
from ssh_security_app.ui.action_requests import MANUAL_UNBLOCK_ACTION


@dataclass(frozen=True)
class ActionCycleResult:
    examined: int
    completed: int
    rejected: int
    failed: int


class ActionRequestWorker:
    """Privileged worker that validates pending requests before firewall changes."""

    component_name = "action_request_worker"

    def __init__(
        self,
        *,
        firewall: FirewallManager,
        requests: ActionRequestRepository,
        blocks: BlockRepository,
        audit: AuditService,
        health: HealthMonitor,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.firewall = firewall
        self.requests = requests
        self.blocks = blocks
        self.audit = audit
        self.health = health
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def process_once(self, *, limit: int = 100) -> ActionCycleResult:
        pending = self.requests.list_pending(limit)
        completed = 0
        rejected = 0
        failed = 0
        for request in pending:
            outcome = self._process_request(request)
            if outcome is ActionRequestStatus.COMPLETED:
                completed += 1
            elif outcome is ActionRequestStatus.REJECTED:
                rejected += 1
            else:
                failed += 1

        if failed:
            self.health.degraded(
                self.component_name,
                f"{failed} manual action request(s) failed",
                examined=len(pending),
                completed=completed,
                rejected=rejected,
                failed=failed,
            )
        else:
            self.health.healthy(
                self.component_name,
                examined=len(pending),
                completed=completed,
                rejected=rejected,
                failed=0,
            )
        return ActionCycleResult(len(pending), completed, rejected, failed)

    def _process_request(self, request: ActionRequest) -> ActionRequestStatus:
        if request.action_type != MANUAL_UNBLOCK_ACTION:
            return self._finish(
                request,
                ActionRequestStatus.REJECTED,
                "unsupported action type",
            )
        try:
            normalized_ip = str(ipaddress.IPv4Address(request.source_ip))
        except ipaddress.AddressValueError:
            return self._finish(
                request,
                ActionRequestStatus.REJECTED,
                "request contains an invalid IPv4 address",
            )
        block = self.blocks.get(request.block_id)
        if block is None:
            return self._finish(
                request,
                ActionRequestStatus.REJECTED,
                "selected block no longer exists",
            )
        if block.status is not BlockStatus.ACTIVE:
            return self._finish(
                request,
                ActionRequestStatus.REJECTED,
                "selected block is no longer Active",
            )
        if block.source_ip != normalized_ip:
            return self._finish(
                request,
                ActionRequestStatus.REJECTED,
                "request source does not match the selected block",
            )

        try:
            exists = self.firewall.rule_exists(normalized_ip)
        except FirewallError as exc:
            self.blocks.record_error(block.block_id, error_message=str(exc))
            return self._finish(request, ActionRequestStatus.FAILED, str(exc))
        if not exists:
            message = "active database block has no matching project firewall rule"
            self.blocks.mark_removed(
                block.block_id,
                status=BlockStatus.INCONSISTENT,
                removal_method="Manual request validation",
                removed_at=ensure_utc(self.clock()),
                error_message=message,
            )
            return self._finish(request, ActionRequestStatus.REJECTED, message)

        operation = self.firewall.delete_block_rule(normalized_ip)
        if not operation.success:
            self.blocks.record_error(
                block.block_id,
                error_message=operation.message,
                firewall_result=operation.message,
            )
            return self._finish(
                request,
                ActionRequestStatus.FAILED,
                operation.message,
            )

        now = ensure_utc(self.clock())
        if not self.blocks.mark_removed(
            block.block_id,
            status=BlockStatus.MANUALLY_REMOVED,
            removal_method="Manual",
            removed_at=now,
            firewall_result=operation.message,
        ):
            return self._finish(
                request,
                ActionRequestStatus.FAILED,
                "firewall rule was removed but database status changed concurrently",
            )
        return self._finish(
            request,
            ActionRequestStatus.COMPLETED,
            "exact project firewall rule removed",
        )

    def _finish(
        self,
        request: ActionRequest,
        status: ActionRequestStatus,
        message: str,
    ) -> ActionRequestStatus:
        self.requests.complete(
            request.request_id,
            status=status,
            result_message=message,
            processed_at=ensure_utc(self.clock()),
        )
        self.audit.record(
            component=self.component_name,
            action="manual_unblock",
            target=request.source_ip,
            result=status.value.lower(),
            details={
                "block_id": request.block_id,
                "request_id": request.request_id,
                "message": message,
            },
        )
        return status
