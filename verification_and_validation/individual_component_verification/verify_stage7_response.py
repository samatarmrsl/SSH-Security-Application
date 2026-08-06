from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from ssh_security_application.audit import AuditService
from ssh_security_application.config import load_config
from ssh_security_application.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    BlockStatus,
    Decision,
    DetectionClassification,
    IPAddressCategory,
    ParseStatus,
)
from ssh_security_application.health import HealthMonitor
from ssh_security_application.iptables_firewall_response.firewall import (
    ExpirationWorker,
    FirewallManager,
    FirewallReconciler,
    parse_project_rules,
)
from ssh_security_application.main import main
from ssh_security_application.models import (
    AuthenticationEvent,
    BlockRecord,
    Detection,
)
from ssh_security_application.sqlite_data_storage.storage import (
    Database,
    RepositorySet,
)

NOW = datetime(2026, 7, 25, 12, tzinfo=timezone.utc)


def build_context(tmp_path, fake_iptables):
    database = Database(tmp_path / "stage7.db")
    database.initialize()
    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    health = HealthMonitor(repositories.health)
    firewall = FirewallManager(
        load_config().response,
        ssh_port=22,
        runner=fake_iptables,
        on_health=health.record,
    )
    assert firewall.initialize_chain().success
    return repositories, audit, health, firewall


def activate_block(
    repositories: RepositorySet,
    source_ip: str,
    *,
    block_id: str,
    expires_at: datetime,
) -> BlockRecord:
    auth = AuthenticationEvent(
        event_id=f"auth-{block_id}",
        event_time=NOW,
        collected_at=NOW,
        source_ip=source_ip,
        username="test",
        event_type=AuthenticationEventType.FAILED_PASSWORD,
        authentication_result=AuthenticationResult.FAILURE,
        process_id=1,
        raw_message="sanitized",
        parse_status=ParseStatus.PARSED,
    )
    repositories.auth_events.insert(auth)
    repositories.ip_profiles.observe_authentication(auth, IPAddressCategory.PRIVATE)
    detection = Detection(
        detection_id=f"detection-{block_id}",
        source_ip=source_ip,
        window_start=NOW,
        window_end=NOW,
        failed_count=12,
        successful_count=0,
        invalid_user_count=2,
        unique_usernames=4,
        network_connection_count=12,
        attempt_rate=2,
        recent_success=False,
        previous_detection_count=0,
        previous_block_count=0,
        allowlisted=False,
        risk_score=90,
        classification=DetectionClassification.HIGH_RISK,
        decision=Decision.BLOCK,
        decision_reason="unit test",
        created_at=NOW,
        evidence_fingerprint=f"evidence-{block_id}",
    )
    repositories.detections.insert(detection)
    block = BlockRecord(
        block_id=block_id,
        source_ip=source_ip,
        detection_id=detection.detection_id,
        blocked_at=NOW - timedelta(minutes=5),
        expires_at=expires_at,
        removed_at=None,
        status=BlockStatus.ACTIVE,
        removal_method=None,
        firewall_result="inserted",
        error_message=None,
    )
    repositories.blocks.activate(block)
    return block


def test_expiration_worker_removes_exact_rule_and_marks_expired(
    tmp_path,
    fake_iptables,
) -> None:
    repositories, audit, health, firewall = build_context(tmp_path, fake_iptables)
    block = activate_block(
        repositories,
        "192.168.56.40",
        block_id="expired",
        expires_at=NOW,
    )
    assert firewall.insert_block_rule(block.source_ip).success
    worker = ExpirationWorker(
        firewall=firewall,
        blocks=repositories.blocks,
        audit=audit,
        health=health,
        clock=lambda: NOW,
    )

    result = worker.process_once()

    stored = repositories.blocks.get(block.block_id)
    assert result.expired == 1
    assert stored is not None
    assert stored.status is BlockStatus.EXPIRED
    assert stored.removal_method == "Automatic"
    assert stored.removed_at == NOW
    assert block.source_ip not in fake_iptables.blocked_sources


def test_expiration_failure_stays_active_and_retries(
    tmp_path,
    fake_iptables,
) -> None:
    repositories, audit, health, firewall = build_context(tmp_path, fake_iptables)
    block = activate_block(
        repositories,
        "192.168.56.41",
        block_id="retry",
        expires_at=NOW,
    )
    assert firewall.insert_block_rule(block.source_ip).success
    worker = ExpirationWorker(
        firewall=firewall,
        blocks=repositories.blocks,
        audit=audit,
        health=health,
        clock=lambda: NOW,
    )
    fake_iptables.fail_next_change = True

    failed = worker.process_once()
    retried = worker.process_once()

    assert failed.failed == 1
    assert retried.expired == 1
    assert repositories.blocks.get(block.block_id).status is BlockStatus.EXPIRED


def test_terminal_unblock_removes_exact_rule_and_updates_database(
    tmp_path,
    fake_iptables,
    monkeypatch,
    capsys,
) -> None:
    config_path = tmp_path / "unblock.json"
    database_path = tmp_path / "unblock.db"
    config_path.write_text(
        json.dumps(
            {
                "database": {"path": str(database_path)},
                "logging": {"path": str(tmp_path / "unblock.log")},
            }
        ),
        encoding="utf-8",
    )
    database = Database(database_path)
    database.initialize()
    repositories = RepositorySet(database)
    health = HealthMonitor(repositories.health)
    firewall = FirewallManager(
        load_config(config_path).response,
        ssh_port=22,
        runner=fake_iptables,
        on_health=health.record,
    )
    assert firewall.initialize_chain().success
    block = activate_block(
        repositories,
        "192.168.56.42",
        block_id="manual",
        expires_at=NOW + timedelta(minutes=5),
    )
    assert firewall.insert_block_rule(block.source_ip).success
    monkeypatch.setattr(
        "ssh_security_application.main._build_firewall_manager",
        lambda *_args: firewall,
    )

    result = main(["--config", str(config_path), "unblock", block.source_ip])

    assert result == 0
    assert "Manual unblock completed" in capsys.readouterr().out
    assert repositories.blocks.get(block.block_id).status is BlockStatus.MANUALLY_REMOVED
    assert block.source_ip not in fake_iptables.blocked_sources


def test_reconciliation_handles_all_owned_state_cases(
    tmp_path,
    fake_iptables,
) -> None:
    repositories, audit, health, firewall = build_context(tmp_path, fake_iptables)
    current = activate_block(
        repositories,
        "192.168.56.50",
        block_id="current",
        expires_at=NOW + timedelta(minutes=5),
    )
    expired = activate_block(
        repositories,
        "192.168.56.51",
        block_id="expired-reconcile",
        expires_at=NOW,
    )
    missing = activate_block(
        repositories,
        "192.168.56.52",
        block_id="missing",
        expires_at=NOW + timedelta(minutes=5),
    )
    for source in (current.source_ip, expired.source_ip, "192.168.56.99"):
        assert firewall.insert_block_rule(source).success
    reconciler = FirewallReconciler(
        firewall=firewall,
        blocks=repositories.blocks,
        audit=audit,
        health=health,
        clock=lambda: NOW,
    )

    result = reconciler.reconcile()

    assert result.active_consistent == 1
    assert result.expired_removed == 1
    assert result.missing_marked_inconsistent == 1
    assert result.unknown_rules == 1
    assert repositories.blocks.get(expired.block_id).status is BlockStatus.EXPIRED
    assert repositories.blocks.get(missing.block_id).status is BlockStatus.INCONSISTENT
    assert "192.168.56.99" in fake_iptables.blocked_sources


def test_project_rule_parser_rejects_broad_or_foreign_rules() -> None:
    parsed = parse_project_rules(
        (
            "-N SSH_SECURITY_APP",
            "-A SSH_SECURITY_APP -s 192.168.56.40/32 -p tcp --dport 22 -j DROP",
            "-A SSH_SECURITY_APP -s 192.168.56.41/32 -p tcp -m tcp --dport 22 -j DROP",
            "-A SSH_SECURITY_APP -s 192.168.56.0/24 -p tcp --dport 22 -j DROP",
            "-A SSH_SECURITY_APP -s 192.168.57.0/24 -p tcp -m tcp --dport 22 -j DROP",
            "-A SSH_SECURITY_APP -p tcp --dport 80 -j DROP",
        ),
        chain="SSH_SECURITY_APP",
        ssh_port=22,
    )

    assert parsed.sources == ("192.168.56.40", "192.168.56.41")
    assert len(parsed.unknown_rules) == 3
