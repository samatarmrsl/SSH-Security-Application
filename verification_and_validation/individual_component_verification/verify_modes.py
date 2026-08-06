from __future__ import annotations

from ssh_security_application.audit import AuditService
from ssh_security_application.constants import OperatingMode
from ssh_security_application.modes import (
    OperatingModeManager,
)
from ssh_security_application.sqlite_data_storage.storage import (
    Database,
    RepositorySet,
)


def test_mode_transitions_are_persisted_and_audited_once(tmp_path) -> None:
    database = Database(tmp_path / "mode.db")
    database.initialize()
    repositories = RepositorySet(database)
    manager = OperatingModeManager(
        repositories.application_state,
        AuditService(repositories.audit),
    )

    assert manager.activate(OperatingMode.SIMULATION) is OperatingMode.SIMULATION
    manager.activate(OperatingMode.SIMULATION)
    assert manager.activate(OperatingMode.LOG_ONLY) is OperatingMode.LOG_ONLY

    assert manager.active_mode() is OperatingMode.LOG_ONLY
    changes = [
        record for record in repositories.audit.list_recent() if record.action == "mode_change"
    ]
    assert len(changes) == 2
    assert changes[0].details == {
        "current_mode": "log_only",
        "previous_mode": "simulation",
    }


def test_only_automatic_response_allows_firewall_action() -> None:
    assert not OperatingModeManager.allows_firewall_action(OperatingMode.SIMULATION)
    assert not OperatingModeManager.allows_firewall_action(OperatingMode.LOG_ONLY)
    assert OperatingModeManager.allows_firewall_action(OperatingMode.AUTOMATIC_RESPONSE)
