"""Create temporary blocks only after all Stage 6 safety checks pass."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone

from ssh_security_app.audit import AuditService
from ssh_security_app.constants import BlockStatus, Decision
from ssh_security_app.core.ip_validation import validate_ip_address
from ssh_security_app.core.normalization import ensure_utc
from ssh_security_app.db.repositories import (
    AllowlistRepository,
    BlockRepository,
)
from ssh_security_app.models import (
    BlockRecord,
    BlockResponse,
    Detection,
    FirewallOperationResult,
)
from ssh_security_app.response.firewall_manager import FirewallError, FirewallManager


class BlockManager:
    """Coordinate validated firewall and SQLite block creation."""

    def __init__(
        self,
        *,
        firewall: FirewallManager,
        blocks: BlockRepository,
        allowlist: AllowlistRepository,
        audit: AuditService,
        duration_seconds: int,
        protected_addresses: Iterable[str] = (),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if duration_seconds < 1:
            raise ValueError("block duration must be positive")
        self.firewall = firewall
        self.blocks = blocks
        self.allowlist = allowlist
        self.audit = audit
        self.duration = timedelta(seconds=duration_seconds)
        self.protected_addresses = tuple(protected_addresses)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def block_detection(self, detection: Detection) -> BlockResponse:
        now = ensure_utc(self.clock())
        if detection.decision is not Decision.BLOCK:
            return self._reject(
                detection,
                "detection decision does not authorize a firewall block",
            )
        allowlisted = self.allowlist.is_allowlisted(detection.source_ip, at=now)
        validation = validate_ip_address(
            detection.source_ip,
            protected_addresses=self.protected_addresses,
            allowlisted=allowlisted,
        )
        if not validation.eligible_for_automatic_blocking:
            return self._reject(
                detection,
                validation.exclusion_reason or "source is not eligible for blocking",
            )
        if self.blocks.get_active(detection.source_ip) is not None:
            return self._reject(detection, "source already has an active database block")
        try:
            if self.firewall.rule_exists(detection.source_ip):
                return self._reject(
                    detection,
                    "exact firewall rule exists without an active database block",
                )
        except FirewallError as exc:
            return self._reject(detection, f"could not verify duplicate rule: {exc}")

        firewall_result = self.firewall.insert_block_rule(detection.source_ip)
        if not firewall_result.success or not firewall_result.changed:
            return self._reject(
                detection,
                f"firewall block failed: {firewall_result.message}",
                firewall_result=firewall_result,
            )

        block = BlockRecord(
            block_id=str(uuid.uuid4()),
            source_ip=detection.source_ip,
            detection_id=detection.detection_id,
            blocked_at=now,
            expires_at=now + self.duration,
            removed_at=None,
            status=BlockStatus.ACTIVE,
            removal_method=None,
            firewall_result=firewall_result.message,
            error_message=None,
        )
        try:
            self.blocks.activate(block)
        except Exception as exc:
            compensation = self.firewall.delete_block_rule(detection.source_ip)
            message = f"database block activation failed: {exc}"
            if not compensation.success:
                message += f"; firewall rollback also failed: {compensation.message}"
            return self._reject(
                detection,
                message,
                firewall_result=firewall_result,
            )

        self.audit.record(
            component="block_manager",
            action="successful_block",
            target=detection.source_ip,
            result="success",
            details={
                "block_id": block.block_id,
                "detection_id": detection.detection_id,
                "blocked_at": block.blocked_at.isoformat(),
                "expires_at": block.expires_at.isoformat(),
            },
        )
        return BlockResponse(
            True,
            f"source blocked until {block.expires_at.isoformat()}",
            block,
            firewall_result,
        )

    def _reject(
        self,
        detection: Detection,
        message: str,
        *,
        firewall_result: FirewallOperationResult | None = None,
    ) -> BlockResponse:
        self.audit.record(
            component="block_manager",
            action="failed_block",
            target=detection.source_ip,
            result="failure",
            details={"detection_id": detection.detection_id, "error": message},
        )
        return BlockResponse(False, message, firewall_result=firewall_result)
