from __future__ import annotations

from pathlib import Path

import pytest

import ssh_security_app.collectors.auth_journal as auth_journal
from ssh_security_app.collectors.auth_journal import (
    AuthenticationJournalCollector,
    CollectorError,
)
from ssh_security_app.config import AuthenticationSensorConfig
from ssh_security_app.constants import HealthState

FIXTURES = Path(__file__).parents[1] / "fixtures"


def sensor_config(*, enabled: bool = True) -> AuthenticationSensorConfig:
    return AuthenticationSensorConfig(
        enabled=enabled,
        systemd_unit="ssh.service",
        journalctl_path="/usr/bin/journalctl",
        lookback_minutes=10,
    )


def test_build_command_uses_an_argument_list() -> None:
    collector = AuthenticationJournalCollector(sensor_config(), on_line=lambda line: None)

    command = collector.build_command(follow=True, since="-5 minutes")

    assert command == [
        "/usr/bin/journalctl",
        "-u",
        "ssh.service",
        "SYSLOG_IDENTIFIER=sshd",
        "-o",
        "short-iso",
        "--no-pager",
        "--quiet",
        "--since",
        "-5 minutes",
        "-f",
    ]

    fresh_follow = collector.build_command(follow=True)

    assert fresh_follow[-3:] == ["--lines", "0", "-f"]


def test_fixture_mode_processes_each_nonempty_line() -> None:
    lines: list[str] = []
    health = []
    collector = AuthenticationJournalCollector(
        sensor_config(),
        on_line=lambda line: lines.append(line),
        on_health=health.append,
    )

    count = collector.collect_fixture(FIXTURES / "auth_invalid_users.log")

    assert count == 3
    assert len(lines) == 3
    assert health[-1].status is HealthState.HEALTHY
    assert health[-1].details["records_processed"] == 3


def test_missing_fixture_reports_failure(tmp_path) -> None:
    health = []
    collector = AuthenticationJournalCollector(
        sensor_config(),
        on_line=lambda line: None,
        on_health=health.append,
    )

    with pytest.raises(CollectorError, match="could not read fixture"):
        collector.collect_fixture(tmp_path / "missing.log")

    assert health[-1].status is HealthState.FAILED


def test_disabled_collector_does_not_start_journalctl() -> None:
    health = []
    collector = AuthenticationJournalCollector(
        sensor_config(enabled=False),
        on_line=lambda line: None,
        on_health=health.append,
    )

    assert collector.collect_once() == 0
    assert health[-1].status is HealthState.STOPPED


def test_one_shot_collects_subprocess_output_without_a_shell(monkeypatch) -> None:
    lines = []
    observed = {}

    class FakeProcess:
        returncode = 0

        def communicate(self):
            return (
                "2026-07-24T08:00:01+00:00 host sshd[1]: "
                "Failed password for root from 192.168.56.2 port 40000 ssh2\n",
                "",
            )

    def fake_popen(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(auth_journal.subprocess, "Popen", fake_popen)
    collector = AuthenticationJournalCollector(
        sensor_config(),
        on_line=lambda line: lines.append(line),
    )

    count = collector.collect_once(since="-1 minute")

    assert count == 1
    assert len(lines) == 1
    assert observed["kwargs"]["shell"] is False
    assert observed["command"][-2:] == ["--since", "-1 minute"]


def test_one_shot_reports_journalctl_failure(monkeypatch) -> None:
    health = []

    class FakeProcess:
        returncode = 1

        def communicate(self):
            return "", "permission denied"

    monkeypatch.setattr(
        auth_journal.subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(),
    )
    collector = AuthenticationJournalCollector(
        sensor_config(),
        on_line=lambda line: None,
        on_health=health.append,
    )

    with pytest.raises(CollectorError, match="permission denied"):
        collector.collect_once()

    assert health[-1].status is HealthState.FAILED


def test_process_start_error_is_wrapped(monkeypatch) -> None:
    def fail_to_start(*args, **kwargs):
        raise FileNotFoundError("journalctl missing")

    monkeypatch.setattr(auth_journal.subprocess, "Popen", fail_to_start)
    collector = AuthenticationJournalCollector(sensor_config(), on_line=lambda line: None)

    with pytest.raises(CollectorError, match="could not start journalctl"):
        collector.collect_once()
