from __future__ import annotations

from pathlib import Path

from ssh_guard.audit import AuditService
from ssh_guard.collectors.auth_ingestor import AuthenticationIngestor
from ssh_guard.collectors.auth_journal import AuthenticationJournalCollector
from ssh_guard.config import AuthenticationSensorConfig
from ssh_guard.db.database import Database
from ssh_guard.db.repositories import RepositorySet
from ssh_guard.health import HealthMonitor

FIXTURES = Path(__file__).parents[1] / "fixtures"


def build_pipeline(tmp_path):
    database = Database(tmp_path / "integration.db")
    database.initialize()
    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    health = HealthMonitor(repositories.health)
    ingestor = AuthenticationIngestor(
        auth_events=repositories.auth_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        protected_addresses=["192.168.56.10"],
    )
    collector = AuthenticationJournalCollector(
        AuthenticationSensorConfig(
            enabled=True,
            systemd_unit="ssh.service",
            journalctl_path="/usr/bin/journalctl",
            lookback_minutes=10,
        ),
        on_line=ingestor.process_line,
        on_health=health.record,
    )
    return repositories, collector


def test_fixture_to_sqlite_pipeline(tmp_path) -> None:
    repositories, collector = build_pipeline(tmp_path)

    processed = collector.collect_fixture(FIXTURES / "auth_normal.log")

    assert processed == 3
    assert repositories.auth_events.count() == 3
    assert repositories.parser_errors.count() == 0
    profile = repositories.ip_profiles.get("192.168.56.20")
    assert profile is not None
    assert profile["successful_count_total"] == 1
    health = repositories.health.get("authentication_sensor")
    assert health is not None
    assert health.details["records_processed"] == 3


def test_failures_and_parser_errors_are_separated(tmp_path) -> None:
    repositories, collector = build_pipeline(tmp_path)

    collector.collect_fixture(FIXTURES / "auth_bruteforce.log")
    collector.collect_fixture(FIXTURES / "auth_malformed.log")

    assert repositories.auth_events.count() == 10
    assert repositories.parser_errors.count() == 3
    profile = repositories.ip_profiles.get("192.168.56.40")
    assert profile is not None
    assert profile["failed_count_total"] == 10
    audit_records = repositories.audit.list_recent()
    assert sum(record.action == "parser_failure" for record in audit_records) == 3
