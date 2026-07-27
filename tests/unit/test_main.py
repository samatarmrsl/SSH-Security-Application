from __future__ import annotations

import json
from pathlib import Path

from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.main import main

FIXTURES = Path(__file__).parents[1] / "fixtures"


def write_local_config(tmp_path, extra=None):
    config = {
        "database": {"path": str(tmp_path / "cli.db")},
        "logging": {"path": str(tmp_path / "cli.log")},
    }
    if extra:
        for section, values in extra.items():
            config.setdefault(section, {}).update(values)
    path = tmp_path / "local.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_validate_config_command(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path)

    result = main(["--config", str(config), "validate-config"])

    assert result == 0
    assert "Mode=simulation" in capsys.readouterr().out


def test_invalid_config_command_returns_two(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path, {"response": {"mode": "invalid"}})

    result = main(["--config", str(config), "validate-config"])

    assert result == 2
    assert "Configuration error" in capsys.readouterr().err


def test_init_database_command(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path)

    result = main(["--config", str(config), "init-db"])

    assert result == 0
    assert (tmp_path / "cli.db").exists()
    assert "Database initialized" in capsys.readouterr().out
    repositories = RepositorySet(Database(tmp_path / "cli.db"))
    assert repositories.health.get("database") is not None
    assert repositories.audit.list_recent()[0].action == "database_initialized"


def test_mode_status_persists_configured_mode(tmp_path, capsys) -> None:
    config = write_local_config(
        tmp_path,
        {"response": {"mode": "log_only"}},
    )

    result = main(["--config", str(config), "mode-status"])

    assert result == 0
    assert "active mode=log_only" in capsys.readouterr().out
    repositories = RepositorySet(Database(tmp_path / "cli.db"))
    assert repositories.application_state.get("operating_mode") == "log_only"


def test_firewall_initialization_requires_mode_and_confirmation(
    tmp_path,
    capsys,
) -> None:
    simulation = write_local_config(tmp_path)

    result = main(
        [
            "--config",
            str(simulation),
            "firewall-init",
            "--confirm-firewall-changes",
        ]
    )

    assert result == 2
    assert "automatic_response" in capsys.readouterr().err

    automatic = write_local_config(
        tmp_path,
        {"response": {"mode": "automatic_response"}},
    )
    result = main(["--config", str(automatic), "firewall-init"])

    assert result == 2
    assert "--confirm-firewall-changes" in capsys.readouterr().err


def test_apply_response_requires_automatic_mode(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path)

    result = main(
        [
            "--config",
            str(config),
            "detect",
            "--all",
            "--apply-response",
        ]
    )

    assert result == 2
    assert "requires response.mode=automatic_response" in capsys.readouterr().err


def test_fixture_collection_command(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path)

    result = main(
        [
            "--config",
            str(config),
            "collect-auth",
            "--fixture",
            str(FIXTURES / "auth_invalid_users.log"),
        ]
    )

    assert result == 0
    assert "stored_events=3" in capsys.readouterr().out
    repositories = RepositorySet(Database(tmp_path / "cli.db"))
    assert repositories.auth_events.count() == 3
    assert repositories.ip_profiles.get("192.168.56.30")["failed_count_total"] == 2


def test_network_fixture_command(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path)

    result = main(
        [
            "--config",
            str(config),
            "collect-network",
            "--fixture",
            str(FIXTURES / "network_normal.log"),
        ]
    )

    assert result == 0
    assert "stored_events=3" in capsys.readouterr().out
    repositories = RepositorySet(Database(tmp_path / "cli.db"))
    assert repositories.network_events.count() == 3


def test_full_fixture_detection_command(tmp_path, capsys) -> None:
    config = write_local_config(
        tmp_path,
        {"network_sensor": {"protected_ipv4_addresses": ["192.168.56.10"]}},
    )
    common = ["--config", str(config)]
    assert (
        main(
            [
                *common,
                "collect-auth",
                "--fixture",
                str(FIXTURES / "auth_bruteforce.log"),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                *common,
                "collect-network",
                "--fixture",
                str(FIXTURES / "network_bruteforce.log"),
            ]
        )
        == 0
    )
    capsys.readouterr()

    result = main(
        [
            *common,
            "detect",
            "--source-ip",
            "192.168.56.40",
            "--window-end",
            "2026-07-24T08:25:00+00:00",
        ]
    )

    output = capsys.readouterr().out
    assert result == 0
    assert "score=80" in output
    assert "classification=High Risk" in output
    assert "decision=WOULD_BLOCK" in output
    repositories = RepositorySet(Database(tmp_path / "cli.db"))
    assert repositories.health.get("correlation_engine").status.value == "HEALTHY"

    capsys.readouterr()
    inspect_result = main(
        [
            *common,
            "inspect",
            "detections",
            "--limit",
            "1",
        ]
    )
    stored = json.loads(capsys.readouterr().out)

    assert inspect_result == 0
    assert stored[0]["source_ip"] == "192.168.56.40"
    assert stored[0]["network_connections"] == 10
    assert stored[0]["risk_score"] == 80


def test_log_only_fixture_detection_never_creates_a_block(tmp_path, capsys) -> None:
    config = write_local_config(
        tmp_path,
        {
            "response": {"mode": "log_only"},
            "network_sensor": {"protected_ipv4_addresses": ["192.168.56.10"]},
        },
    )
    common = ["--config", str(config)]
    assert (
        main(
            [
                *common,
                "collect-auth",
                "--fixture",
                str(FIXTURES / "auth_bruteforce.log"),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                *common,
                "collect-network",
                "--fixture",
                str(FIXTURES / "network_bruteforce.log"),
            ]
        )
        == 0
    )
    capsys.readouterr()

    result = main(
        [
            *common,
            "detect",
            "--source-ip",
            "192.168.56.40",
            "--window-end",
            "2026-07-24T08:25:00+00:00",
        ]
    )

    assert result == 0
    assert "decision=LOG_DETECTION" in capsys.readouterr().out
    repositories = RepositorySet(Database(tmp_path / "cli.db"))
    assert repositories.blocks.get_active("192.168.56.40") is None


def test_response_commands_require_automatic_mode(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path)

    result = main(["--config", str(config), "response-reconcile"])

    assert result == 2
    assert "automatic_response" in capsys.readouterr().err


def test_invalid_manual_unblock_request_is_reported(tmp_path, capsys) -> None:
    config = write_local_config(tmp_path)

    result = main(
        [
            "--config",
            str(config),
            "manual-unblock-request",
            "missing-block",
            "192.168.56.40",
            "--reason",
            "unit test",
        ]
    )

    assert result == 2
    assert "block does not exist" in capsys.readouterr().err


def test_service_command_builds_unprivileged_pipeline_and_stops(
    tmp_path,
    monkeypatch,
) -> None:
    config = write_local_config(tmp_path)
    controllers = []

    class FakeController:
        def __init__(self, **kwargs):
            controllers.append(kwargs)

        def run(self, stop_event):
            stop_event.set()

    monkeypatch.setattr("ssh_security_app.main.ApplicationController", FakeController)

    result = main(["--config", str(config), "service"])

    assert result == 0
    assert len(controllers) == 1
    assert controllers[0]["response_worker"] is None
