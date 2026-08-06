from __future__ import annotations

from pathlib import Path

import pytest
from ssh_security_application.config import NetworkSensorConfig
from ssh_security_application.constants import HealthState
from ssh_security_application.evidence_collection.auth import (
    CollectorError,
)
from ssh_security_application.evidence_collection.network import (
    NetworkTcpdumpCollector,
)

FIXTURES = Path(__file__).parents[1] / "sample_input_evidence"


def network_config(*, enabled: bool = True) -> NetworkSensorConfig:
    return NetworkSensorConfig(
        enabled=enabled,
        interface="enp0s8",
        ssh_port=22,
        tcpdump_path="/usr/bin/tcpdump",
        snapshot_length_bytes=96,
        restart_delay_seconds=0,
        max_restart_attempts=0,
        protected_ipv4_addresses=("192.168.56.10",),
    )


def test_command_is_filtered_and_uses_metadata_options() -> None:
    collector = NetworkTcpdumpCollector(network_config(), on_line=lambda line: None)

    assert collector.build_command() == [
        "/usr/bin/tcpdump",
        "-i",
        "enp0s8",
        "-nn",
        "-l",
        "-tt",
        "-s",
        "96",
        "tcp",
        "dst",
        "port",
        "22",
    ]


def test_fixture_mode_processes_each_line() -> None:
    lines = []
    health = []
    collector = NetworkTcpdumpCollector(
        network_config(),
        on_line=lambda line: lines.append(line),
        on_health=health.append,
    )

    count = collector.collect_fixture(FIXTURES / "network_normal.log")

    assert count == 3
    assert len(lines) == 3
    assert health[-1].status is HealthState.HEALTHY


def test_missing_fixture_reports_failure(tmp_path) -> None:
    health = []
    collector = NetworkTcpdumpCollector(
        network_config(),
        on_line=lambda line: None,
        on_health=health.append,
    )

    with pytest.raises(CollectorError, match="could not read fixture"):
        collector.collect_fixture(tmp_path / "missing.log")

    assert health[-1].status is HealthState.FAILED


def test_disabled_live_collector_stops_without_starting() -> None:
    health = []
    collector = NetworkTcpdumpCollector(
        network_config(enabled=False),
        on_line=lambda line: None,
        on_health=health.append,
    )

    assert collector.follow() == 0
    assert health[-1].status is HealthState.STOPPED


def test_start_failure_exhausts_restart_budget(monkeypatch) -> None:
    health = []
    collector = NetworkTcpdumpCollector(
        network_config(),
        on_line=lambda line: None,
        on_health=health.append,
    )

    def fail_to_start(command):
        raise CollectorError("permission denied")

    monkeypatch.setattr(collector, "_start_process", fail_to_start)

    with pytest.raises(CollectorError, match="permission denied"):
        collector.follow()

    assert health[-1].status is HealthState.FAILED
