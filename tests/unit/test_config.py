from __future__ import annotations

import json
from pathlib import Path

import pytest

from ssh_security_app.config import ConfigurationError, load_config
from ssh_security_app.constants import OperatingMode


def test_packaged_defaults_match_committed_defaults() -> None:
    repository_root = Path(__file__).parents[2]
    committed = json.loads(
        (repository_root / "config" / "default.json").read_text(encoding="utf-8")
    )
    packaged = json.loads(
        (repository_root / "src" / "ssh_security_app" / "default_config.json").read_text(
            encoding="utf-8"
        )
    )

    assert packaged == committed


def test_default_configuration_is_safe() -> None:
    settings = load_config()

    assert settings.response.mode is OperatingMode.SIMULATION
    assert settings.response.iptables_path == "/usr/sbin/iptables"
    assert settings.response.command_timeout_seconds == 10
    assert settings.detection.window_seconds == 300
    assert settings.detection.suspicious_failure_threshold == 5
    assert settings.detection.blocking_failure_threshold == 10
    assert settings.network_sensor.ssh_port == 22
    assert settings.network_sensor.tcpdump_path == "/usr/bin/tcpdump"
    assert settings.network_sensor.snapshot_length_bytes == 96
    assert settings.network_sensor.max_restart_attempts == 3
    assert settings.database.wal_mode is True
    assert settings.dashboard.host == "127.0.0.1"


def test_local_file_is_merged_over_defaults(tmp_path) -> None:
    override = tmp_path / "local.json"
    override.write_text(
        json.dumps(
            {
                "application": {"environment": "test"},
                "response": {"mode": "log_only"},
                "database": {"path": "custom.db"},
            }
        ),
        encoding="utf-8",
    )

    settings = load_config(override)

    assert settings.application.name == "SSH Security Application"
    assert settings.application.environment == "test"
    assert settings.response.mode is OperatingMode.LOG_ONLY
    assert settings.response.block_duration_seconds == 1800
    assert settings.database.path == "custom.db"


@pytest.mark.parametrize(
    ("override", "expected_message"),
    [
        ({"response": {"mode": "unsafe"}}, "response.mode"),
        (
            {"detection": {"suspicious_failure_threshold": -1}},
            "detection.suspicious_failure_threshold",
        ),
        (
            {
                "detection": {
                    "suspicious_failure_threshold": 11,
                    "blocking_failure_threshold": 10,
                }
            },
            "blocking_failure_threshold",
        ),
        ({"network_sensor": {"ssh_port": 70000}}, "network_sensor.ssh_port"),
        ({"response": {"iptables_chain": "bad-chain"}}, "response.iptables_chain"),
        ({"response": {"iptables_path": "iptables"}}, "response.iptables_path"),
        ({"dashboard": {"host": "0.0.0.0"}}, "dashboard.host"),
        ({"dashboard": {"host": "8.8.8.8"}}, "dashboard.host"),
        ({"database": {"wal_mode": "yes"}}, "database.wal_mode"),
        (
            {"network_sensor": {"protected_ipv4_addresses": ["not-an-ip"]}},
            "protected_ipv4_addresses",
        ),
        (
            {"network_sensor": {"snapshot_length_bytes": 20}},
            "snapshot_length_bytes",
        ),
    ],
)
def test_invalid_configuration_is_rejected(tmp_path, override, expected_message) -> None:
    config_path = tmp_path / "invalid.json"
    config_path.write_text(json.dumps(override), encoding="utf-8")

    with pytest.raises(ConfigurationError, match=expected_message):
        load_config(config_path)


def test_invalid_json_reports_location(tmp_path) -> None:
    config_path = tmp_path / "broken.json"
    config_path.write_text('{"response": ', encoding="utf-8")

    with pytest.raises(ConfigurationError, match="invalid JSON at line"):
        load_config(config_path)


def test_missing_config_file_is_rejected(tmp_path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_config(tmp_path / "missing.json")
