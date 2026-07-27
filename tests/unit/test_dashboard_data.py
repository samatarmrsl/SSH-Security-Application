from __future__ import annotations

import json
import signal
from threading import Event

from ssh_security_app.constants import HealthState, OperatingMode
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.models import HealthStatus
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
    assert service.allowlist_rows() == []
    assert service.action_request_rows() == []


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
