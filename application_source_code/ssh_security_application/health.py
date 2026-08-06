"""Component-health persistence helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ssh_security_application.constants import HealthState
from ssh_security_application.models import HealthStatus
from ssh_security_application.sqlite_data_storage.storage import (
    HealthRepository,
)


class HealthMonitor:
    def __init__(self, repository: HealthRepository) -> None:
        self.repository = repository

    def healthy(self, component: str, **details: Any) -> HealthStatus:
        status = HealthStatus(
            component=component,
            status=HealthState.HEALTHY,
            last_success=datetime.now(timezone.utc),
            last_error=None,
            details=details,
        )
        self.repository.upsert(status)
        return status

    def degraded(self, component: str, error: str, **details: Any) -> HealthStatus:
        previous = self.repository.get(component)
        status = HealthStatus(
            component=component,
            status=HealthState.DEGRADED,
            last_success=previous.last_success if previous else None,
            last_error=error,
            details=details,
        )
        self.repository.upsert(status)
        return status

    def failed(self, component: str, error: str, **details: Any) -> HealthStatus:
        previous = self.repository.get(component)
        status = HealthStatus(
            component=component,
            status=HealthState.FAILED,
            last_success=previous.last_success if previous else None,
            last_error=error,
            details=details,
        )
        self.repository.upsert(status)
        return status

    def stopped(self, component: str, **details: Any) -> HealthStatus:
        previous = self.repository.get(component)
        status = HealthStatus(
            component=component,
            status=HealthState.STOPPED,
            last_success=previous.last_success if previous else None,
            last_error=previous.last_error if previous else None,
            details=details,
        )
        self.repository.upsert(status)
        return status

    def record(self, status: HealthStatus) -> None:
        previous = self.repository.get(status.component)
        if status.last_success is None and previous is not None:
            status = HealthStatus(
                component=status.component,
                status=status.status,
                last_success=previous.last_success,
                last_error=status.last_error,
                details=status.details,
            )
        self.repository.upsert(status)
