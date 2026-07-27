from __future__ import annotations

from threading import Event
from types import SimpleNamespace

from ssh_security_app.constants import HealthState
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.health import HealthMonitor
from ssh_security_app.response.response_worker import ResponseWorker


class FakeReconciler:
    def __init__(self) -> None:
        self.calls = 0

    def reconcile(self) -> None:
        self.calls += 1


class FakeExpiration:
    def __init__(self, stop_event: Event) -> None:
        self.stop_event = stop_event
        self.calls = 0

    def process_once(self):
        self.calls += 1
        self.stop_event.set()
        return SimpleNamespace(examined=1, expired=1, failed=0)


class FakeActions:
    def __init__(self) -> None:
        self.calls = 0

    def process_once(self):
        self.calls += 1
        return SimpleNamespace(examined=0, completed=0, rejected=0, failed=0)


def test_response_worker_reconciles_processes_and_stops(tmp_path) -> None:
    database = Database(tmp_path / "response-worker.db")
    database.initialize()
    repositories = RepositorySet(database)
    health = HealthMonitor(repositories.health)
    stop_event = Event()
    expiration = FakeExpiration(stop_event)
    actions = FakeActions()
    reconciler = FakeReconciler()
    worker = ResponseWorker(
        expiration=expiration,
        actions=actions,
        reconciler=reconciler,
        health=health,
        interval_seconds=1,
    )

    worker.run(stop_event)

    assert reconciler.calls == 1
    assert expiration.calls == 1
    assert actions.calls == 1
    assert repositories.health.get("response_worker").status is HealthState.STOPPED
