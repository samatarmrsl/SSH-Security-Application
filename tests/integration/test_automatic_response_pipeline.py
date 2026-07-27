from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ssh_security_app.audit import AuditService
from ssh_security_app.collectors.auth_ingestor import AuthenticationIngestor
from ssh_security_app.collectors.auth_journal import AuthenticationJournalCollector
from ssh_security_app.collectors.network_ingestor import NetworkIngestor
from ssh_security_app.collectors.network_tcpdump import NetworkTcpdumpCollector
from ssh_security_app.config import load_config
from ssh_security_app.constants import Decision
from ssh_security_app.core.correlation import DetectionEngine
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.health import HealthMonitor
from ssh_security_app.response.block_manager import BlockManager
from ssh_security_app.response.expiration_worker import ExpirationWorker
from ssh_security_app.response.firewall_manager import FirewallManager
from ssh_security_app.ui.dashboard_data import DashboardDataService

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_high_risk_detection_blocks_with_fully_mocked_firewall(
    tmp_path,
    fake_iptables,
) -> None:
    config_path = tmp_path / "automatic.json"
    config_path.write_text(
        json.dumps(
            {
                "response": {
                    "mode": "automatic_response",
                    "block_duration_seconds": 120,
                },
                "database": {"path": str(tmp_path / "automatic.db")},
                "logging": {"path": str(tmp_path / "automatic.log")},
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
    AuthenticationJournalCollector(
        settings.authentication_sensor,
        on_line=auth_ingestor.process_line,
        on_health=health.record,
    ).collect_fixture(FIXTURES / "auth_bruteforce.log")

    network_ingestor = NetworkIngestor(
        network_events=repositories.network_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        interface_name=settings.network_sensor.interface,
        ssh_port=settings.network_sensor.ssh_port,
    )
    NetworkTcpdumpCollector(
        settings.network_sensor,
        on_line=network_ingestor.process_line,
        on_health=health.record,
    ).collect_fixture(FIXTURES / "network_bruteforce.log")

    firewall = FirewallManager(
        settings.response,
        ssh_port=settings.network_sensor.ssh_port,
        runner=fake_iptables,
        on_health=health.record,
    )
    assert firewall.initialize_chain().success
    block_manager = BlockManager(
        firewall=firewall,
        blocks=repositories.blocks,
        allowlist=repositories.allowlist,
        audit=audit,
        duration_seconds=settings.response.block_duration_seconds,
        protected_addresses=settings.network_sensor.protected_ipv4_addresses,
        clock=lambda: datetime(2026, 7, 25, 12, tzinfo=timezone.utc),
    )
    engine = DetectionEngine(
        database=database,
        repositories=repositories,
        settings=settings,
        audit=audit,
        firewall_manager=firewall,
        block_manager=block_manager,
    )

    detection = engine.run_for_source(
        "192.168.56.40",
        window_end=datetime(2026, 7, 24, 8, 25, tzinfo=timezone.utc),
    )

    assert detection is not None
    assert detection.decision is Decision.BLOCK
    assert engine.block_responses[detection.detection_id].success
    active_block = repositories.blocks.get_active("192.168.56.40")
    assert active_block is not None
    assert active_block.expires_at == datetime(2026, 7, 25, 12, 2, tzinfo=timezone.utc)
    assert fake_iptables.blocked_sources == {"192.168.56.40"}
    active_rows = DashboardDataService(repositories).active_block_rows(
        at=datetime(2026, 7, 25, 12, tzinfo=timezone.utc)
    )
    assert active_rows[0]["remaining_seconds"] == 120

    expiration = ExpirationWorker(
        firewall=firewall,
        blocks=repositories.blocks,
        audit=audit,
        health=health,
        clock=lambda: datetime(2026, 7, 25, 12, tzinfo=timezone.utc) + timedelta(seconds=121),
    )
    expiration_result = expiration.process_once()

    assert expiration_result.expired == 1
    assert repositories.blocks.get_active("192.168.56.40") is None
    assert fake_iptables.blocked_sources == set()
    actions = {record.action for record in repositories.audit.list_recent()}
    assert {
        "risk_score_result",
        "block_decision",
        "detection_creation",
        "successful_block",
        "automatic_unblock",
    } <= actions
