from __future__ import annotations

from datetime import datetime, timezone

from ssh_guard.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    HealthState,
    IPAddressCategory,
    ParseStatus,
)
from ssh_guard.db.database import Database
from ssh_guard.db.repositories import RepositorySet
from ssh_guard.models import AuthenticationEvent, HealthStatus

REQUIRED_TABLES = {
    "auth_events",
    "network_events",
    "ip_profiles",
    "detections",
    "detection_auth_events",
    "detection_network_events",
    "allowlist",
    "blocks",
    "action_requests",
    "audit_log",
    "parser_errors",
    "component_health",
}


def build_database(tmp_path) -> Database:
    database = Database(tmp_path / "ssh_guard.db")
    database.initialize()
    return database


def test_schema_and_pragmas_are_initialized(tmp_path) -> None:
    database = build_database(tmp_path)

    with database.connection() as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]

    assert tables >= REQUIRED_TABLES
    assert foreign_keys == 1
    assert journal_mode.lower() == "wal"
    assert database.check_health() is True


def test_auth_event_and_ip_profile_round_trip(tmp_path) -> None:
    database = build_database(tmp_path)
    repositories = RepositorySet(database)
    now = datetime.now(timezone.utc)
    event = AuthenticationEvent(
        event_id="auth-1",
        event_time=now,
        collected_at=now,
        source_ip="192.168.56.20",
        username="student",
        event_type=AuthenticationEventType.FAILED_PASSWORD,
        authentication_result=AuthenticationResult.FAILURE,
        process_id=123,
        raw_message="sanitized",
        parse_status=ParseStatus.PARSED,
    )

    repositories.auth_events.insert(event)
    repositories.ip_profiles.observe_authentication(event, IPAddressCategory.PRIVATE)

    stored = repositories.auth_events.get("auth-1")
    profile = repositories.ip_profiles.get("192.168.56.20")
    assert stored == event
    assert profile is not None
    assert profile["failed_count_total"] == 1
    assert profile["successful_count_total"] == 0


def test_health_repository_preserves_structured_details(tmp_path) -> None:
    database = build_database(tmp_path)
    repositories = RepositorySet(database)
    now = datetime.now(timezone.utc)
    repositories.health.upsert(
        HealthStatus(
            component="database",
            status=HealthState.HEALTHY,
            last_success=now,
            last_error=None,
            details={"path": "test.db"},
        )
    )

    stored = repositories.health.get("database")

    assert stored is not None
    assert stored.status is HealthState.HEALTHY
    assert stored.details == {"path": "test.db"}
    assert stored.last_success == now


def test_allowlist_repository_expires_entries(tmp_path) -> None:
    database = build_database(tmp_path)
    repository = RepositorySet(database).allowlist
    now = datetime.now(timezone.utc)
    entry_id = repository.add(
        ip_address="192.168.56.50",
        description="lab administrator",
        reason="authorized source",
        created_by="unit-test",
        expires_at=now,
    )

    assert repository.get(entry_id) is not None
    assert repository.expire_old(at=now) == 1
    assert repository.is_allowlisted("192.168.56.50", at=now) is False


def test_parser_error_repository_uses_parameters_for_untrusted_text(tmp_path) -> None:
    database = build_database(tmp_path)
    repository = RepositorySet(database).parser_errors
    raw = "'); DROP TABLE auth_events; --"

    repository.record(sensor="test", raw_message=raw, error_message="unsupported")

    assert repository.count() == 1
    assert repository.list_recent()[0]["raw_message"] == raw
    with database.connection() as connection:
        connection.execute("SELECT COUNT(*) FROM auth_events").fetchone()
