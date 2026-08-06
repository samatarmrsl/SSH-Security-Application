"""Allowlist handling, event correlation, risk scoring, and block decisions."""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ssh_security_application.audit import AuditService
from ssh_security_application.config import DetectionConfig, Settings
from ssh_security_application.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    Decision,
    DetectionClassification,
    HealthState,
    OperatingMode,
)
from ssh_security_application.ip_validation import validate_ip_address
from ssh_security_application.iptables_firewall_response.firewall import (
    BlockManager,
    FirewallManager,
)
from ssh_security_application.models import (
    AuthenticationEvent,
    BlockResponse,
    CorrelationResult,
    Detection,
    IPValidationResult,
    NetworkEvent,
    RiskScoreResult,
)
from ssh_security_application.sqlite_data_storage.storage import (
    AllowlistRepository,
    BlockRepository,
    Database,
    IPProfileRepository,
    RepositorySet,
    from_iso,
)
from ssh_security_application.ssh_brute_force_detection.normalization import (
    ensure_utc,
    evidence_fingerprint,
    normalize_ip,
)


# ---- Risk scoring ----
def calculate_risk_score(correlation: CorrelationResult) -> RiskScoreResult:
    breakdown = {
        "failed_authentication_volume": _failure_points(correlation.failed_count),
        "username_diversity": _username_points(correlation.unique_usernames),
        "network_corroboration": _network_points(correlation.network_connection_count),
        "attempt_rate": _rate_points(correlation.attempt_rate),
        "previous_history": _history_points(
            correlation.previous_detection_count,
            correlation.previous_block_count,
        ),
        "invalid_user_activity": _invalid_user_points(correlation.invalid_user_count),
        "recent_success_adjustment": -10 if correlation.recent_success else 0,
    }
    score = max(0, min(100, sum(breakdown.values())))
    breakdown["total"] = score
    return RiskScoreResult(score=score, breakdown=breakdown)


def _failure_points(count: int) -> int:
    if count >= 10:
        return 40
    if count >= 8:
        return 30
    if count >= 5:
        return 20
    if count >= 3:
        return 10
    return 0


def _username_points(count: int) -> int:
    if count >= 6:
        return 20
    if count >= 4:
        return 15
    if count == 3:
        return 10
    if count == 2:
        return 5
    return 0


def _network_points(count: int) -> int:
    if count >= 10:
        return 15
    if count >= 5:
        return 10
    if count >= 1:
        return 5
    return 0


def _rate_points(rate: float) -> int:
    if rate >= 2:
        return 10
    if rate >= 1:
        return 5
    return 0


def _history_points(previous_detections: int, previous_blocks: int) -> int:
    if previous_blocks > 0:
        return 10
    if previous_detections > 0:
        return 5
    return 0


def _invalid_user_points(count: int) -> int:
    if count >= 3:
        return 5
    if count >= 1:
        return 2
    return 0


# ---- Response classification ----
@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reason: str


@dataclass(frozen=True)
class DecisionContext:
    correlation: CorrelationResult
    score: int
    classification: DetectionClassification
    validation: IPValidationResult
    mode: OperatingMode
    detection_config: DetectionConfig
    authentication_sensor_healthy: bool
    network_sensor_healthy: bool
    database_available: bool
    firewall_manager_healthy: bool = False
    firewall_chain_exists: bool = False


def classify_score(score: int) -> DetectionClassification:
    if not 0 <= score <= 100:
        raise ValueError("risk score must be between 0 and 100")
    if score >= 70:
        return DetectionClassification.HIGH_RISK
    if score >= 50:
        return DetectionClassification.SUSPICIOUS
    if score >= 30:
        return DetectionClassification.UNUSUAL
    return DetectionClassification.LOW_CONCERN


def decide(context: DecisionContext) -> DecisionResult:
    correlation = context.correlation
    if correlation.failed_count < context.detection_config.suspicious_failure_threshold:
        return DecisionResult(
            Decision.STORE_ONLY,
            "Failure count is below the configured detection threshold",
        )
    if context.classification is DetectionClassification.LOW_CONCERN:
        return DecisionResult(Decision.STORE_ONLY, "Risk score is Low Concern")
    if context.classification is DetectionClassification.UNUSUAL:
        return DecisionResult(Decision.DISPLAY, "Unusual activity should be displayed for review")
    if context.classification is DetectionClassification.SUSPICIOUS:
        return DecisionResult(
            Decision.LOG_DETECTION,
            "Suspicious activity is logged but does not meet the high-risk threshold",
        )

    if correlation.failed_count < context.detection_config.blocking_failure_threshold:
        return DecisionResult(
            Decision.LOG_DETECTION,
            "High score did not include enough failed logins for a blocking candidate",
        )
    if context.score < context.detection_config.high_risk_score_threshold:
        return DecisionResult(
            Decision.LOG_DETECTION,
            "Score is below the configured high-risk threshold",
        )
    if correlation.allowlisted:
        return DecisionResult(
            Decision.SUPPRESS_ALLOWLIST,
            "Automatic action is suppressed by an active allowlist entry",
        )
    if not context.validation.eligible_for_automatic_blocking:
        return DecisionResult(
            Decision.LOG_DETECTION,
            context.validation.exclusion_reason or "Source is not eligible for automatic blocking",
        )
    if correlation.currently_blocked:
        return DecisionResult(
            Decision.SUPPRESS_ALREADY_BLOCKED,
            "Source already has an active block",
        )
    if correlation.network_connection_count == 0:
        return DecisionResult(
            Decision.SUPPRESS_NO_NETWORK_EVIDENCE,
            "No matching TCP port 22 evidence exists",
        )
    if not (
        context.authentication_sensor_healthy
        and context.network_sensor_healthy
        and context.database_available
    ):
        return DecisionResult(
            Decision.SUPPRESS_SENSOR_FAILURE,
            "Authentication sensor, network sensor, or database is not healthy",
        )
    if context.mode is OperatingMode.SIMULATION:
        return DecisionResult(
            Decision.WOULD_BLOCK,
            "Simulation Mode: all detection safety conditions passed; no firewall change was made",
        )
    if context.mode is OperatingMode.LOG_ONLY:
        return DecisionResult(
            Decision.LOG_DETECTION,
            "Log Only Mode never changes the firewall",
        )
    if not context.firewall_manager_healthy or not context.firewall_chain_exists:
        return DecisionResult(
            Decision.SUPPRESS_FIREWALL_UNAVAILABLE,
            "Firewall manager is unhealthy or the project chain is unavailable",
        )
    return DecisionResult(
        Decision.BLOCK,
        "All automatic-response safety conditions passed",
    )


# ---- Source IP history ----
class IPProfileManager:
    def __init__(
        self,
        profiles: IPProfileRepository,
        blocks: BlockRepository,
    ) -> None:
        self.profiles = profiles
        self.blocks = blocks

    def get_profile(self, source_ip: str) -> dict[str, Any] | None:
        profile = self.profiles.get(source_ip)
        if profile is None:
            return None
        active_block = self.blocks.get_active(source_ip)
        return {
            **profile,
            "currently_blocked": active_block is not None,
            "active_block_id": active_block.block_id if active_block else None,
        }

    def has_recent_success(
        self,
        source_ip: str,
        *,
        at: datetime,
        recent_success_days: int,
    ) -> bool:
        profile = self.profiles.get(source_ip)
        if profile is None or profile["last_success_at"] is None:
            return False
        reference = at.astimezone(timezone.utc)
        last_success = from_iso(profile["last_success_at"])
        if last_success is None:
            return False
        return last_success >= reference - timedelta(days=recent_success_days)


# ---- Trusted IP allowlist ----
class AllowlistManager:
    def __init__(self, repository: AllowlistRepository, audit: AuditService) -> None:
        self.repository = repository
        self.audit = audit

    def add_allowlist_entry(
        self,
        *,
        ip_address: str,
        description: str,
        reason: str,
        created_by: str,
        expires_at: datetime | None = None,
        notes: str | None = None,
    ) -> str:
        normalized = _validated_ipv4(ip_address)
        entry_id = self.repository.add(
            ip_address=normalized,
            description=description,
            reason=reason,
            created_by=created_by,
            expires_at=expires_at,
            notes=notes,
        )
        self.audit.record(
            component="allowlist",
            action="allowlist_addition",
            target=normalized,
            result="success",
            details={"allowlist_id": entry_id, "reason": reason, "created_by": created_by},
        )
        return entry_id

    def disable_allowlist_entry(self, allowlist_id: str) -> bool:
        entry = self.repository.get(allowlist_id)
        changed = self.repository.disable(allowlist_id)
        self.audit.record(
            component="allowlist",
            action="allowlist_disable",
            target=entry["ip_address"] if entry else allowlist_id,
            result="success" if changed else "not_found_or_inactive",
            details={"allowlist_id": allowlist_id},
        )
        return changed

    def get_allowlist_entry(self, allowlist_id: str) -> dict[str, object] | None:
        return self.repository.get(allowlist_id)

    def is_allowlisted(self, ip_address: str, *, at: datetime | None = None) -> bool:
        try:
            normalized = _validated_ipv4(ip_address)
        except ValueError:
            return False
        return self.repository.is_allowlisted(normalized, at=at)

    def list_active_entries(
        self,
        *,
        at: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        return self.repository.list_active(at=at, limit=limit)

    def expire_old_entries(self, *, at: datetime | None = None) -> int:
        count = self.repository.expire_old(at=at)
        if count:
            self.audit.record(
                component="allowlist",
                action="allowlist_expiration",
                result="success",
                details={"expired_count": count},
            )
        return count


def _validated_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except (AttributeError, ipaddress.AddressValueError) as exc:
        raise ValueError(f"allowlist address must be valid IPv4: {value!r}") from exc


# ---- Event correlation and detection engine ----
def correlate_events(
    *,
    source_ip: str,
    auth_events: list[AuthenticationEvent],
    network_events: list[NetworkEvent],
    window_start: datetime,
    window_end: datetime,
    window_seconds: int,
    recent_success: bool = False,
    previous_detection_count: int = 0,
    previous_block_count: int = 0,
    allowlisted: bool = False,
    currently_blocked: bool = False,
) -> CorrelationResult:
    normalized_source = normalize_ip(source_ip)
    start = ensure_utc(window_start)
    end = ensure_utc(window_end)
    if end < start:
        raise ValueError("correlation window end must not be before its start")
    if window_seconds < 1:
        raise ValueError("window_seconds must be positive")

    matching_auth = [
        event
        for event in auth_events
        if event.source_ip == normalized_source and start <= event.event_time <= end
    ]
    matching_network = [
        event
        for event in network_events
        if event.source_ip == normalized_source and start <= event.event_time <= end
    ]
    failed_types = {
        AuthenticationEventType.FAILED_PASSWORD,
        AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
    }
    invalid_types = {
        AuthenticationEventType.INVALID_USER,
        AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
    }
    failed = [event for event in matching_auth if event.event_type in failed_types]
    successful = [
        event
        for event in matching_auth
        if event.authentication_result is AuthenticationResult.SUCCESS
    ]
    invalid_users = [event for event in matching_auth if event.event_type in invalid_types]
    usernames = {
        event.username
        for event in matching_auth
        if event.event_type in failed_types | {AuthenticationEventType.INVALID_USER}
        and event.username
    }
    times = [event.event_time for event in matching_auth] + [
        event.event_time for event in matching_network
    ]
    attempt_rate = len(failed) / (window_seconds / 60)
    return CorrelationResult(
        source_ip=normalized_source,
        window_start=start,
        window_end=end,
        failed_count=len(failed),
        successful_count=len(successful),
        invalid_user_count=len(invalid_users),
        unique_usernames=len(usernames),
        network_connection_count=len(matching_network),
        attempt_rate=round(attempt_rate, 3),
        first_event_time=min(times) if times else None,
        last_event_time=max(times) if times else None,
        recent_success=recent_success,
        previous_detection_count=previous_detection_count,
        previous_block_count=previous_block_count,
        allowlisted=allowlisted,
        currently_blocked=currently_blocked,
        auth_event_ids=tuple(event.event_id for event in matching_auth),
        network_event_ids=tuple(event.event_id for event in matching_network),
    )


class CorrelationEngine:
    def __init__(self, repositories: RepositorySet, settings: Settings) -> None:
        self.repositories = repositories
        self.settings = settings
        self.profile_manager = IPProfileManager(repositories.ip_profiles, repositories.blocks)

    def candidate_sources(self, *, window_end: datetime) -> list[str]:
        end = ensure_utc(window_end)
        start = end - timedelta(seconds=self.settings.detection.window_seconds)
        return self.repositories.auth_events.list_failure_sources(
            window_start=start,
            window_end=end,
        )

    def correlate(self, source_ip: str, *, window_end: datetime) -> CorrelationResult:
        end = ensure_utc(window_end)
        start = end - timedelta(seconds=self.settings.detection.window_seconds)
        normalized_source = normalize_ip(source_ip)
        auth_events = self.repositories.auth_events.list_window(
            source_ip=normalized_source,
            window_start=start,
            window_end=end,
        )
        network_events = self.repositories.network_events.list_window(
            source_ip=normalized_source,
            window_start=start,
            window_end=end,
            destination_port=self.settings.network_sensor.ssh_port,
        )
        profile = self.repositories.ip_profiles.get(normalized_source) or {}
        return correlate_events(
            source_ip=normalized_source,
            auth_events=auth_events,
            network_events=network_events,
            window_start=start,
            window_end=end,
            window_seconds=self.settings.detection.window_seconds,
            recent_success=self.profile_manager.has_recent_success(
                normalized_source,
                at=end,
                recent_success_days=self.settings.detection.recent_success_days,
            ),
            previous_detection_count=int(profile.get("detection_count", 0)),
            previous_block_count=int(profile.get("block_count", 0)),
            allowlisted=self.repositories.allowlist.is_allowlisted(normalized_source, at=end),
            currently_blocked=self.repositories.blocks.get_active(normalized_source) is not None,
        )


class DetectionEngine:
    def __init__(
        self,
        *,
        database: Database,
        repositories: RepositorySet,
        settings: Settings,
        audit: AuditService,
        firewall_manager: FirewallManager | None = None,
        block_manager: BlockManager | None = None,
    ) -> None:
        self.database = database
        self.repositories = repositories
        self.settings = settings
        self.audit = audit
        self.correlation = CorrelationEngine(repositories, settings)
        self.firewall_manager = firewall_manager
        self.block_manager = block_manager
        self.block_responses: dict[str, BlockResponse] = {}

    def run_for_source(
        self,
        source_ip: str,
        *,
        window_end: datetime | None = None,
    ) -> Detection | None:
        end = ensure_utc(window_end or datetime.now(timezone.utc))
        correlation = self.correlation.correlate(source_ip, window_end=end)
        if correlation.failed_count < self.settings.detection.suspicious_failure_threshold:
            return None

        score_result = calculate_risk_score(correlation)
        classification = classify_score(score_result.score)
        validation = validate_ip_address(
            correlation.source_ip,
            protected_addresses=self.settings.network_sensor.protected_ipv4_addresses,
            allowlisted=correlation.allowlisted,
        )
        auth_health = self.repositories.health.get("authentication_sensor")
        network_health = self.repositories.health.get("network_sensor")
        firewall_healthy = False
        firewall_chain_exists = False
        if self.firewall_manager is not None and self.block_manager is not None:
            firewall_healthy, firewall_chain_exists = self.firewall_manager.inspect_readiness()
        decision_result = decide(
            DecisionContext(
                correlation=correlation,
                score=score_result.score,
                classification=classification,
                validation=validation,
                mode=self.settings.response.mode,
                detection_config=self.settings.detection,
                authentication_sensor_healthy=bool(
                    auth_health and auth_health.status is HealthState.HEALTHY
                ),
                network_sensor_healthy=bool(
                    network_health and network_health.status is HealthState.HEALTHY
                ),
                database_available=self.database.check_health(),
                firewall_manager_healthy=firewall_healthy,
                firewall_chain_exists=firewall_chain_exists,
            )
        )
        fingerprint = evidence_fingerprint(
            correlation.source_ip,
            correlation.auth_event_ids,
            correlation.network_event_ids,
        )
        detection = Detection(
            detection_id=str(uuid.uuid4()),
            source_ip=correlation.source_ip,
            window_start=correlation.window_start,
            window_end=correlation.window_end,
            failed_count=correlation.failed_count,
            successful_count=correlation.successful_count,
            invalid_user_count=correlation.invalid_user_count,
            unique_usernames=correlation.unique_usernames,
            network_connection_count=correlation.network_connection_count,
            attempt_rate=correlation.attempt_rate,
            recent_success=correlation.recent_success,
            previous_detection_count=correlation.previous_detection_count,
            previous_block_count=correlation.previous_block_count,
            allowlisted=correlation.allowlisted,
            risk_score=score_result.score,
            classification=classification,
            decision=decision_result.decision,
            decision_reason=decision_result.reason,
            created_at=datetime.now(timezone.utc),
            risk_breakdown=score_result.breakdown,
            evidence_fingerprint=fingerprint,
        )
        inserted = self.repositories.detections.insert(
            detection,
            auth_event_ids=correlation.auth_event_ids,
            network_event_ids=correlation.network_event_ids,
        )
        if not inserted:
            return None

        self.repositories.ip_profiles.increment_detection_count(correlation.source_ip)
        self.audit.record(
            component="risk_score",
            action="risk_score_result",
            target=detection.detection_id,
            result="success",
            details={
                "source_ip": detection.source_ip,
                "risk_score": detection.risk_score,
                "classification": detection.classification.value,
                "breakdown": detection.risk_breakdown,
            },
        )
        self.audit.record(
            component="decision_engine",
            action="block_decision",
            target=detection.detection_id,
            result=detection.decision.value,
            details={
                "source_ip": detection.source_ip,
                "reason": detection.decision_reason,
                "mode": self.settings.response.mode.value,
            },
        )
        self.audit.record(
            component="correlation_engine",
            action="detection_creation",
            target=detection.detection_id,
            result="success",
            details={
                "source_ip": detection.source_ip,
                "risk_score": detection.risk_score,
                "classification": detection.classification.value,
                "decision": detection.decision.value,
                "risk_breakdown": detection.risk_breakdown,
            },
        )
        if detection.decision is Decision.BLOCK and self.block_manager is not None:
            self.block_responses[detection.detection_id] = self.block_manager.block_detection(
                detection
            )
        return detection

    def run_all(self, *, window_end: datetime | None = None) -> list[Detection]:
        end = ensure_utc(window_end or datetime.now(timezone.utc))
        detections = []
        for source_ip in self.correlation.candidate_sources(window_end=end):
            detection = self.run_for_source(source_ip, window_end=end)
            if detection is not None:
                detections.append(detection)
        return detections
