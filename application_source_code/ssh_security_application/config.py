"""JSON configuration loading and validation."""

from __future__ import annotations

import ipaddress
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ssh_security_application.constants import OperatingMode

DEFAULT_CONFIG_PATH = Path(__file__).with_name("default_config.json")
_CHAIN_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,27}$")
_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


class ConfigurationError(ValueError):
    """Raised when configuration cannot be loaded or validated."""


@dataclass(frozen=True)
class ApplicationConfig:
    name: str
    environment: str


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: int
    suspicious_failure_threshold: int
    blocking_failure_threshold: int
    high_risk_score_threshold: int
    recent_success_days: int


@dataclass(frozen=True)
class ResponseConfig:
    mode: OperatingMode
    block_duration_seconds: int
    expiration_check_seconds: int
    firewall_backend: str
    iptables_chain: str
    iptables_path: str
    command_timeout_seconds: int


@dataclass(frozen=True)
class AuthenticationSensorConfig:
    enabled: bool
    systemd_unit: str
    journalctl_path: str
    lookback_minutes: int


@dataclass(frozen=True)
class NetworkSensorConfig:
    enabled: bool
    interface: str
    ssh_port: int
    tcpdump_path: str
    snapshot_length_bytes: int
    restart_delay_seconds: int
    max_restart_attempts: int
    protected_ipv4_addresses: tuple[str, ...]


@dataclass(frozen=True)
class DatabaseConfig:
    path: str
    busy_timeout_seconds: int
    wal_mode: bool


@dataclass(frozen=True)
class LoggingConfig:
    level: str
    path: str
    max_bytes: int
    backup_count: int


@dataclass(frozen=True)
class Settings:
    application: ApplicationConfig
    detection: DetectionConfig
    response: ResponseConfig
    authentication_sensor: AuthenticationSensorConfig
    network_sensor: NetworkSensorConfig
    database: DatabaseConfig
    logging: LoggingConfig


def load_config(config_path: str | Path | None = None) -> Settings:
    """Load defaults and optionally merge a local JSON configuration file."""

    defaults = _read_json(DEFAULT_CONFIG_PATH, "default configuration")
    merged = deepcopy(defaults)
    if config_path is not None:
        override_path = Path(config_path)
        overrides = _read_json(override_path, "configuration override")
        merged = _deep_merge(merged, overrides)
    return _build_settings(merged)


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"{description} file does not exist: {path}") from exc
    except PermissionError as exc:
        raise ConfigurationError(f"{description} file is not readable: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"{description} contains invalid JSON at line {exc.lineno}, column {exc.colno}: {path}"
        ) from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"{description} must contain a JSON object: {path}")
    return value


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(dict(base[key]), value)
        else:
            base[key] = value
    return base


def _build_settings(data: dict[str, Any]) -> Settings:
    application = _section(data, "application")
    detection = _section(data, "detection")
    response = _section(data, "response")
    authentication_sensor = _section(data, "authentication_sensor")
    network_sensor = _section(data, "network_sensor")
    database = _section(data, "database")
    logging_section = _section(data, "logging")

    mode_value = _required_string(response, "mode", "response")
    try:
        mode = OperatingMode(mode_value)
    except ValueError as exc:
        valid_modes = ", ".join(item.value for item in OperatingMode)
        raise ConfigurationError(
            f"response.mode must be one of: {valid_modes}; received {mode_value!r}"
        ) from exc

    detection_config = DetectionConfig(
        window_seconds=_nonnegative_int(detection, "window_seconds", "detection", minimum=1),
        suspicious_failure_threshold=_nonnegative_int(
            detection, "suspicious_failure_threshold", "detection"
        ),
        blocking_failure_threshold=_nonnegative_int(
            detection, "blocking_failure_threshold", "detection"
        ),
        high_risk_score_threshold=_bounded_int(
            detection, "high_risk_score_threshold", "detection", minimum=0, maximum=100
        ),
        recent_success_days=_nonnegative_int(detection, "recent_success_days", "detection"),
    )
    if detection_config.blocking_failure_threshold < detection_config.suspicious_failure_threshold:
        raise ConfigurationError(
            "detection.blocking_failure_threshold must be greater than or equal to "
            "detection.suspicious_failure_threshold"
        )

    firewall_backend = _required_string(response, "firewall_backend", "response")
    if firewall_backend != "iptables":
        raise ConfigurationError("response.firewall_backend must be 'iptables'")
    chain = _required_string(response, "iptables_chain", "response")
    if not _CHAIN_PATTERN.fullmatch(chain):
        raise ConfigurationError(
            "response.iptables_chain must contain 1-28 uppercase letters, digits, or "
            "underscores and start with a letter"
        )

    addresses = network_sensor.get("protected_ipv4_addresses")
    if not isinstance(addresses, list) or not all(isinstance(item, str) for item in addresses):
        raise ConfigurationError(
            "network_sensor.protected_ipv4_addresses must be a list of strings"
        )
    for address in addresses:
        try:
            ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as exc:
            raise ConfigurationError(
                "network_sensor.protected_ipv4_addresses must contain valid IPv4 addresses; "
                f"received {address!r}"
            ) from exc

    log_level = _required_string(logging_section, "level", "logging").upper()
    if log_level not in _LOG_LEVELS:
        raise ConfigurationError(f"logging.level must be one of: {', '.join(sorted(_LOG_LEVELS))}")

    iptables_path = _required_string(response, "iptables_path", "response")
    if not Path(iptables_path).is_absolute():
        raise ConfigurationError("response.iptables_path must be an absolute path")
    return Settings(
        application=ApplicationConfig(
            name=_required_string(application, "name", "application"),
            environment=_required_string(application, "environment", "application"),
        ),
        detection=detection_config,
        response=ResponseConfig(
            mode=mode,
            block_duration_seconds=_nonnegative_int(
                response, "block_duration_seconds", "response", minimum=1
            ),
            expiration_check_seconds=_nonnegative_int(
                response, "expiration_check_seconds", "response", minimum=1
            ),
            firewall_backend=firewall_backend,
            iptables_chain=chain,
            iptables_path=iptables_path,
            command_timeout_seconds=_nonnegative_int(
                response,
                "command_timeout_seconds",
                "response",
                minimum=1,
            ),
        ),
        authentication_sensor=AuthenticationSensorConfig(
            enabled=_required_bool(authentication_sensor, "enabled", "authentication_sensor"),
            systemd_unit=_required_string(
                authentication_sensor, "systemd_unit", "authentication_sensor"
            ),
            journalctl_path=_required_string(
                authentication_sensor, "journalctl_path", "authentication_sensor"
            ),
            lookback_minutes=_nonnegative_int(
                authentication_sensor, "lookback_minutes", "authentication_sensor"
            ),
        ),
        network_sensor=NetworkSensorConfig(
            enabled=_required_bool(network_sensor, "enabled", "network_sensor"),
            interface=_required_string(network_sensor, "interface", "network_sensor"),
            ssh_port=_bounded_int(
                network_sensor, "ssh_port", "network_sensor", minimum=1, maximum=65535
            ),
            tcpdump_path=_required_string(network_sensor, "tcpdump_path", "network_sensor"),
            snapshot_length_bytes=_bounded_int(
                network_sensor,
                "snapshot_length_bytes",
                "network_sensor",
                minimum=40,
                maximum=262144,
            ),
            restart_delay_seconds=_nonnegative_int(
                network_sensor,
                "restart_delay_seconds",
                "network_sensor",
            ),
            max_restart_attempts=_nonnegative_int(
                network_sensor,
                "max_restart_attempts",
                "network_sensor",
            ),
            protected_ipv4_addresses=tuple(addresses),
        ),
        database=DatabaseConfig(
            path=_required_string(database, "path", "database"),
            busy_timeout_seconds=_nonnegative_int(database, "busy_timeout_seconds", "database"),
            wal_mode=_required_bool(database, "wal_mode", "database"),
        ),
        logging=LoggingConfig(
            level=log_level,
            path=_required_string(logging_section, "path", "logging"),
            max_bytes=_nonnegative_int(logging_section, "max_bytes", "logging", minimum=1),
            backup_count=_nonnegative_int(logging_section, "backup_count", "logging"),
        ),
    )


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ConfigurationError(f"required configuration section {key!r} is missing or invalid")
    return value


def _required_string(section: dict[str, Any], key: str, section_name: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{section_name}.{key} must be a non-empty string")
    return value.strip()


def _required_bool(section: dict[str, Any], key: str, section_name: str) -> bool:
    value = section.get(key)
    if not isinstance(value, bool):
        raise ConfigurationError(f"{section_name}.{key} must be true or false")
    return value


def _nonnegative_int(
    section: dict[str, Any],
    key: str,
    section_name: str,
    minimum: int = 0,
) -> int:
    return _bounded_int(section, key, section_name, minimum=minimum)


def _bounded_int(
    section: dict[str, Any],
    key: str,
    section_name: str,
    minimum: int,
    maximum: int | None = None,
) -> int:
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{section_name}.{key} must be an integer")
    if value < minimum:
        raise ConfigurationError(f"{section_name}.{key} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{section_name}.{key} must be no greater than {maximum}")
    return value
