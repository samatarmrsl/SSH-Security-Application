"""Shared enums and constants for SSH Security Application."""

from enum import Enum


class StringEnum(str, Enum):
    """A JSON- and SQLite-friendly string enum."""

    def __str__(self) -> str:
        return self.value


class OperatingMode(StringEnum):
    SIMULATION = "simulation"
    LOG_ONLY = "log_only"
    AUTOMATIC_RESPONSE = "automatic_response"


class AuthenticationResult(StringEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"


class AuthenticationEventType(StringEnum):
    FAILED_PASSWORD = "failed_password"
    FAILED_PASSWORD_INVALID_USER = "failed_password_invalid_user"
    INVALID_USER = "invalid_user"
    ACCEPTED_PASSWORD = "accepted_password"
    ACCEPTED_PUBLIC_KEY = "accepted_public_key"
    CONNECTION_CLOSED = "connection_closed"


class ParseStatus(StringEnum):
    PARSED = "parsed"
    UNSUPPORTED = "unsupported"
    MALFORMED = "malformed"
    INVALID_IP = "invalid_ip"


class IPAddressCategory(StringEnum):
    PRIVATE = "Private"
    GLOBALLY_REACHABLE = "Globally reachable"
    LOOPBACK = "Loopback"
    LINK_LOCAL = "Link-local"
    MULTICAST = "Multicast"
    UNSPECIFIED = "Unspecified"
    RESERVED_OR_SPECIAL_PURPOSE = "Reserved or special-purpose"
    INVALID = "Invalid"


class DetectionClassification(StringEnum):
    LOW_CONCERN = "Low Concern"
    UNUSUAL = "Unusual"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"


class Decision(StringEnum):
    STORE_ONLY = "STORE_ONLY"
    DISPLAY = "DISPLAY"
    LOG_DETECTION = "LOG_DETECTION"
    WOULD_BLOCK = "WOULD_BLOCK"
    BLOCK = "BLOCK"
    SUPPRESS_ALLOWLIST = "SUPPRESS_ALLOWLIST"
    SUPPRESS_NO_NETWORK_EVIDENCE = "SUPPRESS_NO_NETWORK_EVIDENCE"
    SUPPRESS_ALREADY_BLOCKED = "SUPPRESS_ALREADY_BLOCKED"
    SUPPRESS_SENSOR_FAILURE = "SUPPRESS_SENSOR_FAILURE"
    SUPPRESS_FIREWALL_UNAVAILABLE = "SUPPRESS_FIREWALL_UNAVAILABLE"


class BlockStatus(StringEnum):
    ACTIVE = "Active"
    EXPIRED = "Expired"
    MANUALLY_REMOVED = "Manually Removed"
    INCONSISTENT = "Inconsistent"
    FAILED = "Failed"


class HealthState(StringEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"
