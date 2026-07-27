from __future__ import annotations

from threading import Event

from ssh_security_app.audit import AuditService
from ssh_security_app.constants import HealthState
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.health import HealthMonitor
from ssh_security_app.service import ApplicationController


class FakeCollector:
    def __init__(self) -> None:
        self.stopped = Event()

    def follow(self, **_kwargs: object) -> int:
        self.stopped.wait(2)
        return 0

    def stop(self) -> None:
        self.stopped.set()


class StopAfterDetection:
    def __init__(self, stop_event: Event) -> None:
        self.stop_event = stop_event
        self.calls = 0

    def run_all(self) -> list[object]:
        self.calls += 1
        self.stop_event.set()
        return []


def test_application_controller_starts_and_stops_components(tmp_path) -> None:
    database = Database(tmp_path / "service.db")
    database.initialize()
    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    health = HealthMonitor(repositories.health)
    stop_event = Event()
    auth = FakeCollector()
    network = FakeCollector()
    detector = StopAfterDetection(stop_event)
    controller = ApplicationController(
        authentication_collector=auth,
        network_collector=network,
        detector=detector,
        response_worker=None,
        audit=audit,
        health=health,
        detection_interval_seconds=1,
    )

    controller.run(stop_event)

    assert detector.calls == 1
    assert auth.stopped.is_set()
    assert network.stopped.is_set()
    assert repositories.health.get("application_controller").status is HealthState.STOPPED
