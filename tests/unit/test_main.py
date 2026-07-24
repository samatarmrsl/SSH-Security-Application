from __future__ import annotations

import json
from pathlib import Path

from ssh_guard.db.database import Database
from ssh_guard.db.repositories import RepositorySet
from ssh_guard.main import main

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
