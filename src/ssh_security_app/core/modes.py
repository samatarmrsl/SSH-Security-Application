"""Persistent operating-mode activation and audit behavior."""

from __future__ import annotations

from ssh_security_app.audit import AuditService
from ssh_security_app.constants import OperatingMode
from ssh_security_app.db.repositories import ApplicationStateRepository

OPERATING_MODE_STATE_KEY = "operating_mode"


class OperatingModeManager:
    """Track the configured mode and audit real mode transitions."""

    def __init__(
        self,
        state: ApplicationStateRepository,
        audit: AuditService,
    ) -> None:
        self.state = state
        self.audit = audit

    def activate(self, mode: OperatingMode) -> OperatingMode:
        previous_value = self.state.get(OPERATING_MODE_STATE_KEY)
        if previous_value == mode.value:
            return mode
        self.state.set(OPERATING_MODE_STATE_KEY, mode.value)
        self.audit.record(
            component="operating_mode",
            action="mode_change",
            target=mode.value,
            result="success",
            details={"previous_mode": previous_value, "current_mode": mode.value},
        )
        return mode

    def active_mode(self) -> OperatingMode | None:
        value = self.state.get(OPERATING_MODE_STATE_KEY)
        if value is None:
            return None
        return OperatingMode(value)

    @staticmethod
    def allows_firewall_action(mode: OperatingMode) -> bool:
        return mode is OperatingMode.AUTOMATIC_RESPONSE
