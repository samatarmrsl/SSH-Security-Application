"""Score classification and explainable response decisions."""

from __future__ import annotations

from dataclasses import dataclass

from ssh_security_app.config import DetectionConfig
from ssh_security_app.constants import (
    Decision,
    DetectionClassification,
    OperatingMode,
)
from ssh_security_app.models import CorrelationResult, IPValidationResult


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
