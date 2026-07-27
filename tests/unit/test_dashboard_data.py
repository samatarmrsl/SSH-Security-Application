from __future__ import annotations

import json
import signal
from datetime import datetime, timedelta, timezone
from threading import Event

import pytest

from ssh_security_app.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    BlockStatus,
    Decision,
    DetectionClassification,
    HealthState,
    IPAddressCategory,
    OperatingMode,
    ParseStatus,
)
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.models import (
    AuthenticationEvent,
    BlockRecord,
    Detection,
    HealthStatus,
    NetworkEvent,
)
from ssh_security_app.ui.dashboard import main
from ssh_security_app.ui.dashboard_data import DashboardDataService


def test_dashboard_overview_reports_mode_health_and_counts(tmp_path) -> None:
    database = Database(tmp_path / "dashboard.db")
    database.initialize()
    repositories = RepositorySet(database)
    repositories.health.upsert(
        HealthStatus(
            component="authentication_sensor",
            status=HealthState.HEALTHY,
            last_success=None,
            last_error=None,
        )
    )
    service = DashboardDataService(repositories)

    overview = service.overview(OperatingMode.LOG_ONLY)

    assert overview.operating_mode == "log_only"
    assert overview.authentication_sensor_status == "HEALTHY"
    assert overview.network_sensor_status == "STOPPED"
    assert overview.firewall_status == "NOT REQUIRED"
    assert overview.authentication_events == 0
    assert overview.high_risk_detections == 0
    assert service.detection_rows() == []
    assert service.active_block_rows() == []
    assert service.block_history_rows() == []
    assert service.allowlist_rows() == []
    assert service.action_request_rows() == []
    assert service.ip_detail("192.168.56.40") is None
    with pytest.raises(ValueError, match="valid IP"):
        service.ip_detail("not-an-ip")


def test_dashboard_reports_removed_block_and_complete_ip_detail(tmp_path) -> None:
    database = Database(tmp_path / "dashboard-ip-detail.db")
    database.initialize()
    repositories = RepositorySet(database)
    now = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
    source_ip = "192.168.12.3"
    auth = AuthenticationEvent(
        event_id="auth-detail",
        event_time=now,
        collected_at=now,
        source_ip=source_ip,
        username="demo_admin",
        event_type=AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
        authentication_result=AuthenticationResult.FAILURE,
        process_id=100,
        raw_message="sanitized",
        parse_status=ParseStatus.PARSED,
    )
    network = NetworkEvent(
        event_id="network-detail",
        event_time=now,
        collected_at=now,
        source_ip=source_ip,
        destination_ip="192.168.12.1",
        source_port=45000,
        destination_port=22,
        tcp_flags="S",
        interface_name="ens37",
        sensor_name="tcpdump",
        parse_status=ParseStatus.PARSED,
    )
    detection = Detection(
        detection_id="detection-detail",
        source_ip=source_ip,
        window_start=now - timedelta(minutes=5),
        window_end=now,
        failed_count=10,
        successful_count=0,
        invalid_user_count=10,
        unique_usernames=5,
        network_connection_count=10,
        attempt_rate=2.0,
        recent_success=False,
        previous_detection_count=0,
        previous_block_count=0,
        allowlisted=False,
        risk_score=90,
        classification=DetectionClassification.HIGH_RISK,
        decision=Decision.BLOCK,
        decision_reason="corroborated high-risk SSH failures",
        created_at=now,
        risk_breakdown={"failed_attempts": 40, "network_connections": 15},
    )
    block = BlockRecord(
        block_id="block-detail",
        source_ip=source_ip,
        detection_id=detection.detection_id,
        blocked_at=now,
        expires_at=now + timedelta(minutes=2),
        removed_at=None,
        status=BlockStatus.ACTIVE,
        removal_method=None,
        firewall_result="exact rule inserted",
        error_message=None,
    )

    repositories.auth_events.insert(auth)
    repositories.ip_profiles.observe_authentication(auth, IPAddressCategory.PRIVATE)
    repositories.network_events.insert(network)
    repositories.ip_profiles.observe_network(network, IPAddressCategory.PRIVATE)
    repositories.detections.insert(detection)
    repositories.ip_profiles.increment_detection_count(source_ip)
    repositories.blocks.activate(block)
    repositories.blocks.mark_removed(
        block.block_id,
        status=BlockStatus.EXPIRED,
        removal_method="Automatic",
        removed_at=block.expires_at,
        firewall_result="exact rule removed",
    )

    service = DashboardDataService(repositories)
    history = service.block_history_rows(at=block.expires_at)
    detail = service.ip_detail(source_ip)

    assert history[0]["status"] == "Expired"
    assert history[0]["removed"] is True
    assert history[0]["removed_at"] == block.expires_at.isoformat()
    assert history[0]["removal_method"] == "Automatic"
    assert history[0]["removal_summary"] == "Temporary rule removed automatically"
    assert history[0]["iptables_input_jump_rule"] == (
        "-A INPUT -p tcp -m tcp --dport 22 -j SSH_SECURITY_APP"
    )
    assert history[0]["iptables_drop_rule"] == (
        "-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp -m tcp --dport 22 -j DROP"
    )
    assert history[0]["iptables_insert_command"] == (
        "/usr/sbin/iptables -w 5 -I SSH_SECURITY_APP 1 -s 192.168.12.3 -p tcp --dport 22 -j DROP"
    )
    assert detail is not None
    assert detail["profile"]["current_block_status"] == "Expired"
    assert detail["profile"]["authentication_event_count"] == 1
    assert detail["profile"]["network_event_count"] == 1
    assert detail["profile"]["recent_usernames"] == ["demo_admin"]
    assert detail["latest_detection"]["risk_score"] == 90
    assert detail["latest_detection"]["risk_breakdown"]["failed_attempts"] == 40
    assert detail["blocks"][0]["status"] == "Expired"
    assert "raw_message" not in detail["authentication_events"][0]


def test_dashboard_entrypoint_records_unprivileged_action_boundary(
    tmp_path,
    monkeypatch,
) -> None:
    database_path = tmp_path / "dashboard-main.db"
    config_path = tmp_path / "dashboard.json"
    config_path.write_text(
        json.dumps(
            {
                "database": {"path": str(database_path)},
                "dashboard": {"host": "127.0.0.1", "port": 8501},
                "logging": {"path": str(tmp_path / "dashboard.log")},
            }
        ),
        encoding="utf-8",
    )
    served = []
    handlers = {}
    shutdown_called = Event()
    monkeypatch.setattr(
        "ssh_security_app.ui.dashboard.signal.getsignal",
        lambda _signal: "previous-handler",
    )

    def capture_handler(monitored_signal, handler) -> None:
        if handler != "previous-handler":
            handlers[monitored_signal] = handler

    monkeypatch.setattr(
        "ssh_security_app.ui.dashboard.signal.signal",
        capture_handler,
    )

    class FakeServer:
        def __init__(self, address, application) -> None:
            served.append((address, application))

        def serve_forever(self) -> None:
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            assert shutdown_called.wait(timeout=1)

        def shutdown(self) -> None:
            shutdown_called.set()

        def server_close(self) -> None:
            return None

    assert main(["--config", str(config_path)], server_factory=FakeServer) == 0

    assert served[0][0] == ("127.0.0.1", 8501)
    assert shutdown_called.is_set()
    assert served[0][1].snapshot()["overview"]["operating_mode"] == "simulation"
    repositories = RepositorySet(Database(database_path))
    health = repositories.health.get("dashboard")
    assert health.status is HealthState.STOPPED
    assert repositories.application_state.get("operating_mode") == "simulation"
