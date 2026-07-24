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
