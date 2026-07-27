from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ssh_security_app.audit import AuditService
from ssh_security_app.collectors.network_ingestor import NetworkIngestor
from ssh_security_app.collectors.network_tcpdump import NetworkTcpdumpCollector
from ssh_security_app.config import NetworkSensorConfig
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.health import HealthMonitor

FIXTURES = Path(__file__).parents[1] / "fixtures"


def build_pipeline(tmp_path):
    database = Database(tmp_path / "network.db")
    database.initialize()
    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    health = HealthMonitor(repositories.health)
    config = NetworkSensorConfig(
        enabled=True,
        interface="enp0s8",
        ssh_port=22,
        tcpdump_path="/usr/bin/tcpdump",
        snapshot_length_bytes=96,
        restart_delay_seconds=0,
        max_restart_attempts=0,
        protected_ipv4_addresses=("192.168.56.10",),
    )
    ingestor = NetworkIngestor(
        network_events=repositories.network_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        interface_name=config.interface,
        ssh_port=config.ssh_port,
    )
    collector = NetworkTcpdumpCollector(
        config,
        on_line=ingestor.process_line,
        on_health=health.record,
    )
    return repositories, collector, ingestor


def test_fixture_to_sqlite_network_pipeline(tmp_path) -> None:
    repositories, collector, _ = build_pipeline(tmp_path)

    assert collector.collect_fixture(FIXTURES / "network_normal.log") == 3
    assert repositories.network_events.count() == 3
    assert repositories.parser_errors.count() == 0
    events = repositories.network_events.list_window(
        source_ip="192.168.56.20",
        window_start=datetime(2026, 7, 24, 8, tzinfo=timezone.utc),
        window_end=datetime(2026, 7, 24, 9, tzinfo=timezone.utc),
    )
    event = repositories.network_events.get(events[0].event_id)
    assert event is not None
    assert event.destination_port == 22
    assert event.tcp_flags == "S"
    assert repositories.ip_profiles.get("192.168.56.20") is not None
    assert repositories.health.get("network_sensor").details["records_processed"] == 3


def test_network_errors_are_quarantined_and_duplicates_are_suppressed(tmp_path) -> None:
    repositories, collector, ingestor = build_pipeline(tmp_path)

    collector.collect_fixture(FIXTURES / "network_malformed.log")
    line = (FIXTURES / "network_bruteforce.log").read_text(encoding="utf-8").splitlines()[0]
    assert ingestor.process_line(line) is not None
    assert ingestor.process_line(line) is None

    assert repositories.parser_errors.count() == 4
    assert repositories.network_events.count() == 1
