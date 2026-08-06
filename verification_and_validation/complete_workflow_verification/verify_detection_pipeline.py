from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ssh_security_application.audit import AuditService
from ssh_security_application.config import (
    AuthenticationSensorConfig,
    NetworkSensorConfig,
    load_config,
)
from ssh_security_application.constants import (
    Decision,
    DetectionClassification,
)
from ssh_security_application.evidence_collection.auth import (
    AuthenticationIngestor,
    AuthenticationJournalCollector,
)
from ssh_security_application.evidence_collection.network import (
    NetworkIngestor,
    NetworkTcpdumpCollector,
)
from ssh_security_application.health import HealthMonitor
from ssh_security_application.sqlite_data_storage.storage import (
    Database,
    RepositorySet,
)
from ssh_security_application.ssh_brute_force_detection.detection import (
    DetectionEngine,
)

FIXTURES = Path(__file__).parents[1] / "sample_input_evidence"


def test_auth_plus_network_to_high_risk_simulation_detection(tmp_path) -> None:
    config_path = tmp_path / "local.json"
    config_path.write_text(
        json.dumps(
            {
                "database": {"path": str(tmp_path / "detection.db")},
                "logging": {"path": str(tmp_path / "detection.log")},
                "network_sensor": {
                    "interface": "enp0s8",
                    "protected_ipv4_addresses": ["192.168.56.10"],
                },
            }
        ),
        encoding="utf-8",
    )
    settings = load_config(config_path)
    database = Database(settings.database.path)
    database.initialize()
    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    health = HealthMonitor(repositories.health)

    auth_ingestor = AuthenticationIngestor(
        auth_events=repositories.auth_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        protected_addresses=settings.network_sensor.protected_ipv4_addresses,
    )
    auth_collector = AuthenticationJournalCollector(
        AuthenticationSensorConfig(
            enabled=True,
            systemd_unit="ssh.service",
            journalctl_path="/usr/bin/journalctl",
            lookback_minutes=10,
        ),
        on_line=auth_ingestor.process_line,
        on_health=health.record,
    )
    network_ingestor = NetworkIngestor(
        network_events=repositories.network_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        interface_name=settings.network_sensor.interface,
        ssh_port=settings.network_sensor.ssh_port,
    )
    network_collector = NetworkTcpdumpCollector(
        NetworkSensorConfig(
            enabled=True,
            interface="enp0s8",
            ssh_port=22,
            tcpdump_path="/usr/bin/tcpdump",
            snapshot_length_bytes=96,
            restart_delay_seconds=0,
            max_restart_attempts=0,
            protected_ipv4_addresses=("192.168.56.10",),
        ),
        on_line=network_ingestor.process_line,
        on_health=health.record,
    )

    auth_collector.collect_fixture(FIXTURES / "auth_bruteforce.log")
    network_collector.collect_fixture(FIXTURES / "network_bruteforce.log")
    engine = DetectionEngine(
        database=database,
        repositories=repositories,
        settings=settings,
        audit=audit,
    )
    window_end = datetime(2026, 7, 24, 8, 25, tzinfo=timezone.utc)

    detection = engine.run_for_source("192.168.56.40", window_end=window_end)

    assert detection is not None
    assert detection.failed_count == 10
    assert detection.unique_usernames == 4
    assert detection.network_connection_count == 10
    assert detection.attempt_rate == 2
    assert detection.risk_score == 80
    assert detection.classification is DetectionClassification.HIGH_RISK
    assert detection.decision is Decision.WOULD_BLOCK
    assert repositories.detections.count() == 1
    assert repositories.ip_profiles.get("192.168.56.40")["detection_count"] == 1

    assert engine.run_for_source("192.168.56.40", window_end=window_end) is None
    assert repositories.detections.count() == 1

    with database.connection() as connection:
        auth_links = connection.execute("SELECT COUNT(*) FROM detection_auth_events").fetchone()[0]
        network_links = connection.execute(
            "SELECT COUNT(*) FROM detection_network_events"
        ).fetchone()[0]
    assert auth_links == 10
    assert network_links == 10
