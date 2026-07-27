"""Typed domain models used across SSH Security Application."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ssh_security_app.constants import (
    ActionRequestStatus,
    AuthenticationEventType,
    AuthenticationResult,
    BlockStatus,
    Decision,
    DetectionClassification,
    HealthState,
    IPAddressCategory,
    ParseStatus,
)


@dataclass(frozen=True)
class AuthenticationEvent:
    event_id: str
    event_time: datetime
    collected_at: datetime
    source_ip: str
    username: str | None
    event_type: AuthenticationEventType
    authentication_result: AuthenticationResult
    process_id: int | None
    raw_message: str
    parse_status: ParseStatus
    deduplication_key: str | None = None


@dataclass(frozen=True)
class NetworkEvent:
    event_id: str
    event_time: datetime
    collected_at: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    tcp_flags: str
    interface_name: str
    sensor_name: str
    parse_status: ParseStatus
    deduplication_key: str | None = None


@dataclass(frozen=True)
class IPValidationResult:
    original_value: str | None
    normalized_ip: str | None
    is_valid: bool
    ip_version: int | None
    category: IPAddressCategory
    eligible_for_detection: bool
    eligible_for_automatic_blocking: bool
    exclusion_reason: str | None


@dataclass(frozen=True)
class Detection:
    detection_id: str
    source_ip: str
    window_start: datetime
    window_end: datetime
    failed_count: int
    successful_count: int
    invalid_user_count: int
    unique_usernames: int
    network_connection_count: int
    attempt_rate: float
    recent_success: bool
    previous_detection_count: int
    previous_block_count: int
    allowlisted: bool
    risk_score: int
    classification: DetectionClassification
    decision: Decision
    decision_reason: str
    created_at: datetime
    risk_breakdown: dict[str, int] = field(default_factory=dict)
    evidence_fingerprint: str | None = None


@dataclass(frozen=True)
class BlockRecord:
    block_id: str
    source_ip: str
    detection_id: str
    blocked_at: datetime
    expires_at: datetime
    removed_at: datetime | None
    status: BlockStatus
    removal_method: str | None
    firewall_result: str | None
    error_message: str | None


@dataclass(frozen=True)
class ActionRequest:
    request_id: str
    action_type: str
    source_ip: str
    block_id: str
    requested_at: datetime
    requested_reason: str
    status: ActionRequestStatus
    processed_at: datetime | None
    result_message: str | None


@dataclass(frozen=True)
class HealthStatus:
    component: str
    status: HealthState
    last_success: datetime | None
    last_error: str | None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthenticationParseResult:
    status: ParseStatus
    event: AuthenticationEvent | None
    error_message: str | None = None


@dataclass(frozen=True)
class NetworkParseResult:
    status: ParseStatus
    event: NetworkEvent | None
    error_message: str | None = None


@dataclass(frozen=True)
class CorrelationResult:
    source_ip: str
    window_start: datetime
    window_end: datetime
    failed_count: int
    successful_count: int
    invalid_user_count: int
    unique_usernames: int
    network_connection_count: int
    attempt_rate: float
    first_event_time: datetime | None
    last_event_time: datetime | None
    recent_success: bool
    previous_detection_count: int
    previous_block_count: int
    allowlisted: bool
    currently_blocked: bool
    auth_event_ids: tuple[str, ...] = ()
    network_event_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskScoreResult:
    score: int
    breakdown: dict[str, int]


@dataclass(frozen=True)
class FirewallCommandResult:
    command: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0


@dataclass(frozen=True)
class FirewallOperationResult:
    success: bool
    changed: bool
    message: str
    command_results: tuple[FirewallCommandResult, ...] = ()


@dataclass(frozen=True)
class BlockResponse:
    success: bool
    message: str
    block: BlockRecord | None = None
    firewall_result: FirewallOperationResult | None = None


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    event_time: datetime
    component: str
    action: str
    target: str | None
    result: str
    details: dict[str, Any] = field(default_factory=dict)
