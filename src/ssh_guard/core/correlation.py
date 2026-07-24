"""Five-minute multi-source correlation and detection orchestration."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from ssh_guard.audit import AuditService
from ssh_guard.config import Settings
from ssh_guard.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    HealthState,
)
from ssh_guard.core.classification import DecisionContext, classify_score, decide
from ssh_guard.core.ip_profiles import IPProfileManager
from ssh_guard.core.ip_validation import validate_ip_address
from ssh_guard.core.normalization import ensure_utc, evidence_fingerprint, normalize_ip
from ssh_guard.core.risk_score import calculate_risk_score
from ssh_guard.db.database import Database
from ssh_guard.db.repositories import RepositorySet
from ssh_guard.models import AuthenticationEvent, CorrelationResult, Detection, NetworkEvent


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
    ) -> None:
        self.database = database
        self.repositories = repositories
        self.settings = settings
        self.audit = audit
        self.correlation = CorrelationEngine(repositories, settings)

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
        return detection

    def run_all(self, *, window_end: datetime | None = None) -> list[Detection]:
        end = ensure_utc(window_end or datetime.now(timezone.utc))
        detections = []
        for source_ip in self.correlation.candidate_sources(window_end=end):
            detection = self.run_for_source(source_ip, window_end=end)
            if detection is not None:
                detections.append(detection)
        return detections
