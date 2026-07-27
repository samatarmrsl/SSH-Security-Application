from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ssh_security_app.constants import OperatingMode
from ssh_security_app.ui.dashboard import (
    DashboardActions,
    DashboardApplication,
    DashboardHTTPServer,
)
from ssh_security_app.ui.dashboard_data import DashboardOverview


class FakeData:
    def overview_dict(self, _mode):
        return {
            "operating_mode": "simulation",
            "authentication_events": 10,
            "network_events": 10,
            "suspicious_detections": 0,
            "high_risk_detections": 1,
            "active_blocks": 1,
            "expired_blocks": 0,
            "manual_removals": 0,
            "recent_parser_errors": 0,
            "authentication_sensor_status": "HEALTHY",
            "network_sensor_status": "HEALTHY",
            "firewall_status": "HEALTHY",
        }

    def overview(self, _mode):
        return DashboardOverview(**self.overview_dict(_mode))

    def detection_rows(self):
        return [{"source_ip": "192.168.56.40", "risk_score": 80}]

    def active_block_rows(self):
        return [
            {
                "block_id": "block-1",
                "source_ip": "192.168.56.40",
                "expires_at": "2026-07-25T12:05:00+00:00",
            }
        ]

    def block_history_rows(self):
        return [
            {
                "block_id": "block-1",
                "source_ip": "192.168.56.40",
                "status": "Expired",
                "removed_at": "2026-07-25T12:05:00+00:00",
                "removal_method": "Automatic",
                "removal_summary": "Temporary rule removed automatically",
                "iptables_input_jump_rule": (
                    "-A INPUT -p tcp -m tcp --dport 22 -j SSH_SECURITY_APP"
                ),
                "iptables_drop_rule": (
                    "-A SSH_SECURITY_APP -s 192.168.56.40/32 -p tcp -m tcp --dport 22 -j DROP"
                ),
                "iptables_insert_command": (
                    "/usr/sbin/iptables -w 5 -I SSH_SECURITY_APP 1 "
                    "-s 192.168.56.40 -p tcp --dport 22 -j DROP"
                ),
            }
        ]

    def ip_detail(self, source_ip):
        if source_ip == "not-an-ip":
            raise ValueError("source_ip must be a valid IP address")
        if source_ip != "192.168.56.40":
            return None
        return {
            "source_ip": source_ip,
            "profile": {
                "ip_category": "Private",
                "failed_authentications": 10,
                "current_block_status": "Expired",
            },
            "detections": [],
            "blocks": self.block_history_rows(),
            "authentication_events": [],
            "network_events": [],
        }

    def allowlist_rows(self):
        return []

    def audit_rows(self):
        return [{"action": "test"}]

    def action_request_rows(self):
        return []

    def health_rows(self):
        return [{"component": "database", "status": "HEALTHY"}]


class FakeManualUnblocks:
    def request(self, **_kwargs):
        return SimpleNamespace(request_id="request-1")


class FakeAllowlist:
    def add_allowlist_entry(self, **_kwargs):
        return "allow-1"

    def disable_allowlist_entry(self, _entry_id):
        return True


@pytest.fixture
def dashboard_server():
    application = DashboardApplication(
        FakeData(),
        OperatingMode.SIMULATION,
        DashboardActions(
            manual_unblocks=FakeManualUnblocks(),
            allowlist=FakeAllowlist(),
        ),
        csrf_token="unit-test-csrf-token",
    )
    server = DashboardHTTPServer(("127.0.0.1", 0), application)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _json_request(url: str, *, token: str | None = None, payload=None):
    headers = {}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-CSRF-Token"] = token
    with urlopen(Request(url, data=data, headers=headers), timeout=2) as response:
        return response.status, json.loads(response.read())


def test_owned_assets_have_no_streamlit_or_external_runtime() -> None:
    static = Path(__file__).parents[2] / "src" / "ssh_security_app" / "ui" / "static"
    combined = "\n".join(
        (static / filename).read_text(encoding="utf-8")
        for filename in ("index.html", "app.css", "app.js")
    )

    assert "SSH Security Application" in combined
    assert "ip-detail-drawer" in combined
    assert "Block lifecycle" in combined
    assert "/api/ip-details" in combined
    assert "SOURCE-SPECIFIC DROP" in combined
    assert "iptables_drop_rule" in combined
    assert "streamlit" not in combined.lower()
    assert "https://" not in combined
    assert "http://" not in combined


def test_dashboard_serves_owned_interface_and_snapshot(dashboard_server) -> None:
    with urlopen(f"{dashboard_server}/", timeout=2) as response:
        html = response.read().decode("utf-8")
        assert response.status == 200
        assert response.headers["X-Frame-Options"] == "DENY"

    _, session = _json_request(f"{dashboard_server}/api/session")
    _, snapshot = _json_request(f"{dashboard_server}/api/snapshot")

    assert "SSH Security Application" in html
    assert session["csrf_token"] == "unit-test-csrf-token"
    assert snapshot["overview"]["operating_mode"] == "simulation"
    assert snapshot["detections"][0]["source_ip"] == "192.168.56.40"
    assert snapshot["block_history"][0]["status"] == "Expired"


def test_dashboard_serves_stored_ip_detail(dashboard_server) -> None:
    status, detail = _json_request(f"{dashboard_server}/api/ip-details?source_ip=192.168.56.40")

    assert status == 200
    assert detail["source_ip"] == "192.168.56.40"
    assert detail["profile"]["current_block_status"] == "Expired"
    assert detail["blocks"][0]["removal_method"] == "Automatic"


def test_dashboard_rejects_invalid_or_unknown_ip_detail(dashboard_server) -> None:
    with pytest.raises(HTTPError) as invalid:
        _json_request(f"{dashboard_server}/api/ip-details?source_ip=not-an-ip")
    assert invalid.value.code == 400

    with pytest.raises(HTTPError) as unknown:
        _json_request(f"{dashboard_server}/api/ip-details?source_ip=192.168.56.99")
    assert unknown.value.code == 404


def test_dashboard_rejects_action_without_csrf(dashboard_server) -> None:
    with pytest.raises(HTTPError) as exc:
        _json_request(
            f"{dashboard_server}/api/actions/allowlist-add",
            payload={
                "ip_address": "192.168.56.20",
                "description": "test",
                "reason": "authorized",
                "created_by": "pytest",
            },
        )

    assert exc.value.code == 403


def test_dashboard_accepts_same_origin_sqlite_action(dashboard_server) -> None:
    status, response = _json_request(
        f"{dashboard_server}/api/actions/allowlist-add",
        token="unit-test-csrf-token",
        payload={
            "ip_address": "192.168.56.20",
            "description": "test",
            "reason": "authorized",
            "created_by": "pytest",
        },
    )

    assert status == 201
    assert response["allowlist_id"] == "allow-1"
