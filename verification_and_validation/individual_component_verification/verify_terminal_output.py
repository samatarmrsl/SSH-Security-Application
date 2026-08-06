from __future__ import annotations

from datetime import datetime, timezone

from ssh_security_application.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    BlockStatus,
    Decision,
    DetectionClassification,
    ParseStatus,
)
from ssh_security_application.models import (
    AuthenticationEvent,
    BlockRecord,
    BlockResponse,
    Detection,
    FirewallOperationResult,
    NetworkEvent,
)
from ssh_security_application.terminal import TerminalInterface


def test_detection_output_includes_source_context_and_firewall_rules(capsys) -> None:
    now = datetime(2026, 8, 6, 17, 30, tzinfo=timezone.utc)
    detection = Detection(
        detection_id="det-1",
        source_ip="192.168.12.3",
        window_start=now,
        window_end=now,
        failed_count=10,
        successful_count=0,
        invalid_user_count=2,
        unique_usernames=6,
        network_connection_count=12,
        attempt_rate=2.0,
        recent_success=False,
        previous_detection_count=0,
        previous_block_count=0,
        allowlisted=False,
        risk_score=90,
        classification=DetectionClassification.HIGH_RISK,
        decision=Decision.BLOCK,
        decision_reason="All automatic-response safety conditions passed",
        created_at=now,
        risk_breakdown={"failed_authentication_volume": 40, "total": 90},
    )
    auth_event = AuthenticationEvent(
        event_id="auth-1",
        event_time=now,
        collected_at=now,
        source_ip="192.168.12.3",
        username="demo_admin",
        event_type=AuthenticationEventType.FAILED_PASSWORD,
        authentication_result=AuthenticationResult.FAILURE,
        process_id=123,
        raw_message="Failed password for demo_admin from 192.168.12.3 port 50000 ssh2",
        parse_status=ParseStatus.PARSED,
    )
    network_event = NetworkEvent(
        event_id="net-1",
        event_time=now,
        collected_at=now,
        source_ip="192.168.12.3",
        destination_ip="192.168.12.1",
        source_port=50000,
        destination_port=22,
        tcp_flags="S",
        interface_name="ens37",
        sensor_name="tcpdump",
        parse_status=ParseStatus.PARSED,
    )

    TerminalInterface().print_detection(
        detection,
        block_response=BlockResponse(
            True,
            "source blocked until 2026-08-06T17:32:00+00:00",
            BlockRecord(
                block_id="block-1",
                source_ip="192.168.12.3",
                detection_id="det-1",
                blocked_at=now,
                expires_at=now,
                removed_at=None,
                status=BlockStatus.ACTIVE,
                removal_method=None,
                firewall_result="exact block rule inserted",
                error_message=None,
            ),
            FirewallOperationResult(True, True, "exact block rule inserted"),
        ),
        block_duration_seconds=120,
        exact_rule="-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP",
        input_jump_rule="-A INPUT -p tcp --dport 22 -j SSH_SECURITY_APP",
        source_profile={
            "ip_category": "Private",
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "failed_count_total": 10,
            "successful_count_total": 0,
            "detection_count": 1,
            "block_count": 0,
            "current_block_status": "Active",
        },
        recent_auth_events=[auth_event],
        recent_network_events=[network_event],
    )

    output = capsys.readouterr().out
    assert "Source machine info: local observations only" in output
    assert "IP category: Private" in output
    assert "Usernames attempted: demo_admin" in output
    assert "TCP source ports seen: 50000" in output
    assert "INPUT jump: -A INPUT -p tcp --dport 22 -j SSH_SECURITY_APP" in output
    assert "DROP rule: -A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP" in output
