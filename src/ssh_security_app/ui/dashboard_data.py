"""Pure data queries used by the complete dashboard."""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ssh_security_app.constants import (
    BlockStatus,
    DetectionClassification,
    HealthState,
    OperatingMode,
)
from ssh_security_app.db.repositories import RepositorySet

_CHAIN_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,27}$")


@dataclass(frozen=True)
class DashboardOverview:
    operating_mode: str
    authentication_sensor_status: str
    network_sensor_status: str
    firewall_status: str
    authentication_events: int
    network_events: int
    suspicious_detections: int
    high_risk_detections: int
    active_blocks: int
    expired_blocks: int
    manual_removals: int
    recent_parser_errors: int


class DashboardDataService:
    """Prepare serializable records for the first-party dashboard."""

    def __init__(
        self,
        repositories: RepositorySet,
        *,
        iptables_path: str = "/usr/sbin/iptables",
        iptables_chain: str = "SSH_SECURITY_APP",
        ssh_port: int = 22,
    ) -> None:
        if not Path(iptables_path).is_absolute():
            raise ValueError("iptables_path must be absolute")
        if not _CHAIN_PATTERN.fullmatch(iptables_chain):
            raise ValueError("iptables_chain must be a valid project chain")
        if not 1 <= ssh_port <= 65535:
            raise ValueError("ssh_port must be between 1 and 65535")
        self.repositories = repositories
        self.iptables_path = iptables_path
        self.iptables_chain = iptables_chain
        self.ssh_port = ssh_port

    def overview(self, mode: OperatingMode) -> DashboardOverview:
        return DashboardOverview(
            operating_mode=mode.value,
            authentication_sensor_status=self._health_value("authentication_sensor"),
            network_sensor_status=self._health_value("network_sensor"),
            firewall_status=(
                self._health_value("firewall_manager")
                if mode is OperatingMode.AUTOMATIC_RESPONSE
                else "NOT REQUIRED"
            ),
            authentication_events=self.repositories.auth_events.count(),
            network_events=self.repositories.network_events.count(),
            suspicious_detections=self.repositories.detections.count_by_classification(
                DetectionClassification.SUSPICIOUS
            ),
            high_risk_detections=self.repositories.detections.count_by_classification(
                DetectionClassification.HIGH_RISK
            ),
            active_blocks=self.repositories.blocks.count_by_status(BlockStatus.ACTIVE),
            expired_blocks=self.repositories.blocks.count_by_status(BlockStatus.EXPIRED),
            manual_removals=self.repositories.blocks.count_by_status(BlockStatus.MANUALLY_REMOVED),
            recent_parser_errors=len(self.repositories.parser_errors.list_recent(limit=10)),
        )

    def detection_rows(
        self,
        limit: int = 100,
        *,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = []
        for detection in self.repositories.detections.list_recent(
            limit=limit,
            source_ip=source_ip,
        ):
            profile = self.repositories.ip_profiles.get(detection.source_ip) or {}
            rows.append(
                {
                    "detection_id": detection.detection_id,
                    "source_ip": detection.source_ip,
                    "ip_category": profile.get("ip_category", "Unknown"),
                    "failed_attempts": detection.failed_count,
                    "successful_attempts": detection.successful_count,
                    "invalid_user_attempts": detection.invalid_user_count,
                    "unique_usernames": detection.unique_usernames,
                    "network_connections": detection.network_connection_count,
                    "attempt_rate": detection.attempt_rate,
                    "window_start": detection.window_start.isoformat(),
                    "window_end": detection.window_end.isoformat(),
                    "recent_success": detection.recent_success,
                    "previous_detections": detection.previous_detection_count,
                    "previous_blocks": detection.previous_block_count,
                    "risk_score": detection.risk_score,
                    "risk_breakdown": detection.risk_breakdown,
                    "classification": detection.classification.value,
                    "allowlisted": detection.allowlisted,
                    "decision": detection.decision.value,
                    "decision_reason": detection.decision_reason,
                    "detection_time": detection.created_at.isoformat(),
                }
            )
        return rows

    def active_block_rows(
        self,
        *,
        at: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        now = at or datetime.now(timezone.utc)
        reconciliation = self.repositories.health.get("firewall_reconciler")
        firewall_state = (
            "Reconciled"
            if reconciliation and reconciliation.status is HealthState.HEALTHY
            else "Pending reconciliation"
        )
        return [
            self._block_row(block, at=now, firewall_state=firewall_state)
            for block in self.repositories.blocks.list_active(limit)
        ]

    def block_history_rows(
        self,
        limit: int = 100,
        *,
        source_ip: str | None = None,
        at: datetime | None = None,
    ) -> list[dict[str, Any]]:
        now = at or datetime.now(timezone.utc)
        return [
            self._block_row(block, at=now)
            for block in self.repositories.blocks.list_recent(
                limit=limit,
                source_ip=source_ip,
            )
        ]

    def ip_detail(self, source_ip: str, *, limit: int = 25) -> dict[str, Any] | None:
        try:
            normalized_ip = str(ipaddress.ip_address(source_ip))
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IP address") from exc
        profile = self.repositories.ip_profiles.get(normalized_ip)
        if profile is None:
            return None

        authentication_events = self.repositories.auth_events.list_recent(
            source_ip=normalized_ip,
            limit=limit,
        )
        network_events = self.repositories.network_events.list_recent(
            source_ip=normalized_ip,
            limit=limit,
        )
        detections = self.detection_rows(limit=limit, source_ip=normalized_ip)
        blocks = self.block_history_rows(limit=limit, source_ip=normalized_ip)
        allowlist = [
            entry
            for entry in self.repositories.allowlist.list_all(limit=1000)
            if entry["ip_address"] == normalized_ip
        ]
        usernames = sorted(
            {
                event.username
                for event in authentication_events
                if event.username is not None and event.username.strip()
            }
        )
        return {
            "source_ip": normalized_ip,
            "profile": {
                "ip_category": profile.get("ip_category", "Unknown"),
                "first_seen": profile.get("first_seen"),
                "last_seen": profile.get("last_seen"),
                "failed_authentications": profile.get("failed_count_total", 0),
                "successful_authentications": profile.get("successful_count_total", 0),
                "last_success_at": profile.get("last_success_at"),
                "detection_count": profile.get("detection_count", 0),
                "block_count": profile.get("block_count", 0),
                "current_block_status": profile.get("current_block_status"),
                "notes": profile.get("notes"),
                "authentication_event_count": self.repositories.auth_events.count(
                    source_ip=normalized_ip
                ),
                "network_event_count": self.repositories.network_events.count(
                    source_ip=normalized_ip
                ),
                "currently_allowlisted": self.repositories.allowlist.is_allowlisted(normalized_ip),
                "recent_usernames": usernames,
            },
            "latest_detection": detections[0] if detections else None,
            "detections": detections,
            "blocks": blocks,
            "authentication_events": [
                {
                    "event_time": event.event_time.isoformat(),
                    "username": event.username,
                    "event_type": event.event_type.value,
                    "result": event.authentication_result.value,
                    "parse_status": event.parse_status.value,
                }
                for event in authentication_events
            ],
            "network_events": [
                {
                    "event_time": event.event_time.isoformat(),
                    "destination_ip": event.destination_ip,
                    "source_port": event.source_port,
                    "destination_port": event.destination_port,
                    "tcp_flags": event.tcp_flags,
                    "interface": event.interface_name,
                    "sensor": event.sensor_name,
                    "parse_status": event.parse_status.value,
                }
                for event in network_events
            ],
            "allowlist": allowlist,
        }

    def allowlist_rows(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.repositories.allowlist.list_all(limit)

    def action_request_rows(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            {
                "request_id": request.request_id,
                "action": request.action_type,
                "source_ip": request.source_ip,
                "block_id": request.block_id,
                "requested_at": request.requested_at.isoformat(),
                "reason": request.requested_reason,
                "status": request.status.value,
                "processed_at": (
                    request.processed_at.isoformat() if request.processed_at else None
                ),
                "result": request.result_message,
            }
            for request in self.repositories.action_requests.list_recent(limit)
        ]

    def audit_rows(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            {
                "event_time": record.event_time.isoformat(),
                "component": record.component,
                "action": record.action,
                "target": record.target,
                "result": record.result,
                "details": record.details,
            }
            for record in self.repositories.audit.list_recent(limit)
        ]

    def health_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "component": item.component,
                "status": item.status.value,
                "last_success": (item.last_success.isoformat() if item.last_success else None),
                "last_error": item.last_error,
                "details": item.details,
            }
            for item in self.repositories.health.list_all()
        ]

    def overview_dict(self, mode: OperatingMode) -> dict[str, Any]:
        return asdict(self.overview(mode))

    def _block_row(
        self,
        block,
        *,
        at: datetime,
        firewall_state: str | None = None,
    ) -> dict[str, Any]:
        normalized_source = str(ipaddress.IPv4Address(block.source_ip))
        source_network = f"{normalized_source}/32"
        input_jump_rule = shlex.join(
            [
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                str(self.ssh_port),
                "-j",
                self.iptables_chain,
            ]
        )
        drop_rule = shlex.join(
            [
                "-A",
                self.iptables_chain,
                "-s",
                source_network,
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                str(self.ssh_port),
                "-j",
                "DROP",
            ]
        )
        insert_command = shlex.join(
            [
                self.iptables_path,
                "-w",
                "5",
                "-I",
                self.iptables_chain,
                "1",
                "-s",
                normalized_source,
                "-p",
                "tcp",
                "--dport",
                str(self.ssh_port),
                "-j",
                "DROP",
            ]
        )
        removed = block.status is not BlockStatus.ACTIVE
        if block.status is BlockStatus.EXPIRED:
            removal_summary = "Temporary rule removed automatically"
        elif block.status is BlockStatus.MANUALLY_REMOVED:
            removal_summary = "Temporary rule removed by operator request"
        elif block.status is BlockStatus.INCONSISTENT:
            removal_summary = "Rule no longer active after reconciliation"
        elif block.status is BlockStatus.FAILED:
            removal_summary = "Firewall response failed"
        else:
            removal_summary = "Temporary rule is active"
        return {
            "block_id": block.block_id,
            "detection_id": block.detection_id,
            "source_ip": block.source_ip,
            "blocked_at": block.blocked_at.isoformat(),
            "expires_at": block.expires_at.isoformat(),
            "remaining_seconds": (
                max(0, int((block.expires_at - at).total_seconds())) if not removed else 0
            ),
            "removed_at": block.removed_at.isoformat() if block.removed_at else None,
            "status": block.status.value,
            "removed": removed,
            "removal_method": block.removal_method,
            "removal_summary": removal_summary,
            "iptables_input_jump_rule": input_jump_rule,
            "iptables_drop_rule": drop_rule,
            "iptables_insert_command": insert_command,
            "firewall_state": firewall_state
            if not removed and firewall_state is not None
            else {
                BlockStatus.EXPIRED: "Rule removed",
                BlockStatus.MANUALLY_REMOVED: "Rule removed",
                BlockStatus.INCONSISTENT: "Rule not confirmed",
                BlockStatus.FAILED: "Rule not active",
            }.get(block.status, "Active rule"),
            "last_firewall_result": block.firewall_result,
            "last_error": block.error_message,
        }

    def _health_value(self, component: str) -> str:
        health = self.repositories.health.get(component)
        return health.status.value if health else HealthState.STOPPED.value
