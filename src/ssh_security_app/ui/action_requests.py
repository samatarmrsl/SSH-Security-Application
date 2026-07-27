"""Unprivileged dashboard service for SQLite-backed action requests."""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from ssh_security_app.audit import AuditService
from ssh_security_app.constants import ActionRequestStatus, BlockStatus
from ssh_security_app.core.normalization import ensure_utc
from ssh_security_app.db.repositories import ActionRequestRepository, BlockRepository
from ssh_security_app.models import ActionRequest

MANUAL_UNBLOCK_ACTION = "manual_unblock"


class ManualUnblockRequestService:
    """Validate and persist a request without firewall access."""

    def __init__(
        self,
        *,
        requests: ActionRequestRepository,
        blocks: BlockRepository,
        audit: AuditService,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.requests = requests
        self.blocks = blocks
        self.audit = audit
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def request(
        self,
        *,
        block_id: str,
        source_ip: str,
        reason: str,
        request_id: str | None = None,
    ) -> ActionRequest:
        normalized_ip = str(ipaddress.IPv4Address(source_ip))
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise ValueError("manual unblock reason is required")
        if len(normalized_reason) > 500:
            raise ValueError("manual unblock reason must be 500 characters or fewer")
        block = self.blocks.get(block_id)
        if block is None:
            raise ValueError("block does not exist")
        if block.status is not BlockStatus.ACTIVE:
            raise ValueError("only an Active block can be manually removed")
        if block.source_ip != normalized_ip:
            raise ValueError("request source does not match the selected block")
        if self.requests.has_pending_for_block(block_id):
            raise ValueError("a manual unblock request is already pending for this block")

        request = ActionRequest(
            request_id=request_id or str(uuid.uuid4()),
            action_type=MANUAL_UNBLOCK_ACTION,
            source_ip=normalized_ip,
            block_id=block_id,
            requested_at=ensure_utc(self.clock()),
            requested_reason=normalized_reason,
            status=ActionRequestStatus.PENDING,
            processed_at=None,
            result_message=None,
        )
        self.requests.insert(request)
        self.audit.record(
            component="dashboard",
            action="manual_unblock_requested",
            target=normalized_ip,
            result="pending",
            details={"block_id": block_id, "request_id": request.request_id},
        )
        return request
