from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ssh_guard.core.risk_score import calculate_risk_score
from ssh_guard.models import CorrelationResult


def correlation(**overrides) -> CorrelationResult:
    values = {
        "source_ip": "192.168.56.40",
        "window_start": datetime(2026, 7, 24, 8, 20, tzinfo=timezone.utc),
        "window_end": datetime(2026, 7, 24, 8, 25, tzinfo=timezone.utc),
        "failed_count": 0,
        "successful_count": 0,
        "invalid_user_count": 0,
        "unique_usernames": 1,
        "network_connection_count": 0,
        "attempt_rate": 0.0,
        "first_event_time": None,
        "last_event_time": None,
        "recent_success": False,
        "previous_detection_count": 0,
        "previous_block_count": 0,
        "allowlisted": False,
        "currently_blocked": False,
    }
    values.update(overrides)
    return CorrelationResult(**values)


def test_full_score_breakdown_is_explainable() -> None:
    result = calculate_risk_score(
        correlation(
            failed_count=10,
            unique_usernames=6,
            network_connection_count=10,
            attempt_rate=2,
            previous_detection_count=2,
            previous_block_count=1,
            invalid_user_count=3,
            recent_success=True,
        )
    )

    assert result.score == 90
    assert result.breakdown == {
        "failed_authentication_volume": 40,
        "username_diversity": 20,
        "network_corroboration": 15,
        "attempt_rate": 10,
        "previous_history": 10,
        "invalid_user_activity": 5,
        "recent_success_adjustment": -10,
        "total": 90,
    }


@pytest.mark.parametrize(
    ("failures", "points"),
    [(0, 0), (3, 10), (5, 20), (8, 30), (10, 40)],
)
def test_failure_score_boundaries(failures, points) -> None:
    result = calculate_risk_score(correlation(failed_count=failures))

    assert result.breakdown["failed_authentication_volume"] == points


def test_score_is_clamped_to_zero() -> None:
    result = calculate_risk_score(correlation(recent_success=True))

    assert result.score == 0
