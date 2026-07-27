"""Pure data queries used by the complete dashboard."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from ssh_security_app.constants import (
    BlockStatus,
    DetectionClassification,
    HealthState,
    OperatingMode,
)
from ssh_security_app.db.repositories import RepositorySet


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

    def __init__(self, repositories: RepositorySet) -> None:
        self.repositories = repositories

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

    def detection_rows(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = []
        for detection in self.repositories.detections.list_recent(limit=limit):
            profile = self.repositories.ip_profiles.get(detection.source_ip) or {}
            rows.append(
                {
                    "detection_id": detection.detection_id,
                    "source_ip": detection.source_ip,
                    "ip_category": profile.get("ip_category", "Unknown"),
                    "failed_attempts": detection.failed_count,
                    "invalid_user_attempts": detection.invalid_user_count,
                    "unique_usernames": detection.unique_usernames,
                    "network_connections": detection.network_connection_count,
                    "attempt_rate": detection.attempt_rate,
                    "risk_score": detection.risk_score,
                    "classification": detection.classification.value,
                    "allowlisted": detection.allowlisted,
                    "decision": detection.decision.value,
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
            {
                "block_id": block.block_id,
                "source_ip": block.source_ip,
                "blocked_at": block.blocked_at.isoformat(),
                "expires_at": block.expires_at.isoformat(),
                "remaining_seconds": max(0, int((block.expires_at - now).total_seconds())),
                "status": block.status.value,
                "firewall_state": firewall_state,
                "last_firewall_result": block.firewall_result,
                "last_error": block.error_message,
            }
            for block in self.repositories.blocks.list_active(limit)
        ]

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

    def _health_value(self, component: str) -> str:
        health = self.repositories.health.get(component)
        return health.status.value if health else HealthState.STOPPED.value
