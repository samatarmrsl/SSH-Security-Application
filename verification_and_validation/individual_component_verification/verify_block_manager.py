from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from ssh_security_application.audit import AuditService
from ssh_security_application.config import load_config
from ssh_security_application.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    Decision,
    DetectionClassification,
    IPAddressCategory,
    ParseStatus,
)
from ssh_security_application.iptables_firewall_response.firewall import (
    BlockManager,
    FirewallManager,
)
from ssh_security_application.models import AuthenticationEvent, Detection
from ssh_security_application.sqlite_data_storage.storage import (
    Database,
    RepositorySet,
)

NOW = datetime(2026, 7, 25, 12, tzinfo=timezone.utc)


def build_detection(decision: Decision = Decision.BLOCK) -> Detection:
    return Detection(
        detection_id="detection-1",
        source_ip="192.168.56.40",
        window_start=NOW,
        window_end=NOW,
        failed_count=10,
        successful_count=0,
        invalid_user_count=0,
        unique_usernames=4,
        network_connection_count=10,
        attempt_rate=2,
        recent_success=False,
        previous_detection_count=0,
        previous_block_count=0,
        allowlisted=False,
        risk_score=80,
        classification=DetectionClassification.HIGH_RISK,
        decision=decision,
        decision_reason="test",
        created_at=NOW,
        risk_breakdown={"total": 80},
        evidence_fingerprint="test-evidence",
    )


def build_manager(tmp_path, fake_iptables):
    settings = load_config()
    database = Database(tmp_path / "block.db")
    database.initialize()
    repositories = RepositorySet(database)
    auth_event = AuthenticationEvent(
        event_id="auth-profile",
        event_time=NOW,
        collected_at=NOW,
        source_ip="192.168.56.40",
        username="test",
        event_type=AuthenticationEventType.FAILED_PASSWORD,
        authentication_result=AuthenticationResult.FAILURE,
        process_id=1,
        raw_message="sanitized",
        parse_status=ParseStatus.PARSED,
    )
    repositories.auth_events.insert(auth_event)
    repositories.ip_profiles.observe_authentication(
        auth_event,
        IPAddressCategory.PRIVATE,
    )
    detection = build_detection()
    repositories.detections.insert(detection)
    firewall = FirewallManager(
        settings.response,
        ssh_port=22,
        runner=fake_iptables,
    )
    assert firewall.initialize_chain().success
    manager = BlockManager(
        firewall=firewall,
        blocks=repositories.blocks,
        allowlist=repositories.allowlist,
        audit=AuditService(repositories.audit),
        duration_seconds=120,
        protected_addresses=("192.168.56.10",),
        clock=lambda: NOW,
    )
    return repositories, manager, detection


def test_approved_detection_creates_confirmed_temporary_block(
    tmp_path,
    fake_iptables,
) -> None:
    repositories, manager, detection = build_manager(tmp_path, fake_iptables)

    response = manager.block_detection(detection)

    assert response.success
    assert response.block is not None
    assert response.block.expires_at.isoformat() == "2026-07-25T12:02:00+00:00"
    assert repositories.blocks.get_active("192.168.56.40") == response.block
    profile = repositories.ip_profiles.get("192.168.56.40")
    assert profile["block_count"] == 1
    assert profile["current_block_status"] == "Active"
    assert fake_iptables.blocked_sources == {"192.168.56.40"}


def test_non_block_decision_is_rejected_without_firewall_change(
    tmp_path,
    fake_iptables,
) -> None:
    repositories, manager, detection = build_manager(tmp_path, fake_iptables)

    response = manager.block_detection(replace(detection, decision=Decision.WOULD_BLOCK))

    assert not response.success
    assert repositories.blocks.get_active("192.168.56.40") is None
    assert fake_iptables.blocked_sources == set()


def test_active_allowlist_is_rechecked_before_firewall_change(
    tmp_path,
    fake_iptables,
) -> None:
    repositories, manager, detection = build_manager(tmp_path, fake_iptables)
    repositories.allowlist.add(
        ip_address=detection.source_ip,
        description="trusted lab source",
        reason="unit test",
        created_by="pytest",
    )

    response = manager.block_detection(detection)

    assert not response.success
    assert "allowlist" in response.message.lower()
    assert fake_iptables.blocked_sources == set()


def test_firewall_insert_failure_does_not_create_database_block(
    tmp_path,
    fake_iptables,
) -> None:
    repositories, manager, detection = build_manager(tmp_path, fake_iptables)
    fake_iptables.fail_next_change = True

    response = manager.block_detection(detection)

    assert not response.success
    assert repositories.blocks.get_active(detection.source_ip) is None
    assert fake_iptables.blocked_sources == set()


def test_database_failure_rolls_back_inserted_firewall_rule(
    tmp_path,
    fake_iptables,
    monkeypatch,
) -> None:
    _repositories, manager, detection = build_manager(tmp_path, fake_iptables)
    monkeypatch.setattr(
        manager.blocks,
        "activate",
        lambda _block: (_ for _ in ()).throw(ValueError("simulated database failure")),
    )

    response = manager.block_detection(detection)

    assert not response.success
    assert "database block activation failed" in response.message
    assert fake_iptables.blocked_sources == set()
