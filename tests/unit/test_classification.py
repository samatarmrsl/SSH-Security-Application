from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ssh_guard.config import DetectionConfig
from ssh_guard.constants import (
    Decision,
    DetectionClassification,
    IPAddressCategory,
    OperatingMode,
)
from ssh_guard.core.classification import DecisionContext, classify_score, decide
from ssh_guard.models import CorrelationResult, IPValidationResult


@pytest.mark.parametrize(
    ("score", "classification"),
    [
        (0, DetectionClassification.LOW_CONCERN),
        (29, DetectionClassification.LOW_CONCERN),
        (30, DetectionClassification.UNUSUAL),
        (49, DetectionClassification.UNUSUAL),
        (50, DetectionClassification.SUSPICIOUS),
        (69, DetectionClassification.SUSPICIOUS),
        (70, DetectionClassification.HIGH_RISK),
        (100, DetectionClassification.HIGH_RISK),
    ],
)
def test_classification_boundaries(score, classification) -> None:
    assert classify_score(score) is classification


def context(**overrides) -> DecisionContext:
    now = datetime(2026, 7, 24, 8, 25, tzinfo=timezone.utc)
    correlation_values = {
        "source_ip": "192.168.56.40",
        "window_start": now,
        "window_end": now,
        "failed_count": 10,
        "successful_count": 0,
        "invalid_user_count": 0,
        "unique_usernames": 4,
        "network_connection_count": 10,
        "attempt_rate": 2,
        "first_event_time": now,
        "last_event_time": now,
        "recent_success": False,
        "previous_detection_count": 0,
        "previous_block_count": 0,
        "allowlisted": False,
        "currently_blocked": False,
    }
    correlation_values.update(overrides.pop("correlation", {}))
    values = {
        "correlation": CorrelationResult(**correlation_values),
        "score": 80,
        "classification": DetectionClassification.HIGH_RISK,
        "validation": IPValidationResult(
            original_value="192.168.56.40",
            normalized_ip="192.168.56.40",
            is_valid=True,
            ip_version=4,
            category=IPAddressCategory.PRIVATE,
            eligible_for_detection=True,
            eligible_for_automatic_blocking=True,
            exclusion_reason=None,
        ),
        "mode": OperatingMode.SIMULATION,
        "detection_config": DetectionConfig(300, 5, 10, 70, 30),
        "authentication_sensor_healthy": True,
        "network_sensor_healthy": True,
        "database_available": True,
    }
    values.update(overrides)
    return DecisionContext(**values)


def test_simulation_mode_produces_would_block() -> None:
    assert decide(context()).decision is Decision.WOULD_BLOCK


def test_no_network_evidence_suppresses_action() -> None:
    result = decide(context(correlation={"network_connection_count": 0}))

    assert result.decision is Decision.SUPPRESS_NO_NETWORK_EVIDENCE


def test_allowlist_suppresses_only_high_risk_action() -> None:
    result = decide(context(correlation={"allowlisted": True}))

    assert result.decision is Decision.SUPPRESS_ALLOWLIST


def test_sensor_failure_suppresses_action() -> None:
    result = decide(context(network_sensor_healthy=False))

    assert result.decision is Decision.SUPPRESS_SENSOR_FAILURE


def test_automatic_mode_requires_firewall_health() -> None:
    result = decide(context(mode=OperatingMode.AUTOMATIC_RESPONSE))

    assert result.decision is Decision.SUPPRESS_FIREWALL_UNAVAILABLE


def test_automatic_mode_can_approve_block_without_executing_it() -> None:
    result = decide(
        context(
            mode=OperatingMode.AUTOMATIC_RESPONSE,
            firewall_manager_healthy=True,
            firewall_chain_exists=True,
        )
    )

    assert result.decision is Decision.BLOCK
