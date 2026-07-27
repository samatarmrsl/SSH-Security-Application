"""Explainable 0-100 brute-force risk scoring."""

from __future__ import annotations

from ssh_security_app.models import CorrelationResult, RiskScoreResult


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
