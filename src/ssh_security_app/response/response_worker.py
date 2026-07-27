"""Long-running Stage 7 worker independent of the dashboard process."""

from __future__ import annotations

import logging
from threading import Event

from ssh_security_app.health import HealthMonitor
from ssh_security_app.response.action_request_worker import ActionRequestWorker
from ssh_security_app.response.expiration_worker import ExpirationWorker
from ssh_security_app.response.reconciliation import FirewallReconciler


class ResponseWorker:
    component_name = "response_worker"

    def __init__(
        self,
        *,
        expiration: ExpirationWorker,
        actions: ActionRequestWorker,
        reconciler: FirewallReconciler,
        health: HealthMonitor,
        interval_seconds: int,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("response worker interval must be positive")
        self.expiration = expiration
        self.actions = actions
        self.reconciler = reconciler
        self.health = health
        self.interval_seconds = interval_seconds
        self.logger = logging.getLogger("ssh_security_app.response.response_worker")

    def run(self, stop_event: Event) -> None:
        self.logger.info("response worker starting with startup reconciliation")
        self.reconciler.reconcile()
        self.health.healthy(
            self.component_name,
            interval_seconds=self.interval_seconds,
        )
        try:
            while not stop_event.is_set():
                expiration = self.expiration.process_once()
                actions = self.actions.process_once()
                self.health.healthy(
                    self.component_name,
                    expiration=expiration.__dict__,
                    actions=actions.__dict__,
                )
                stop_event.wait(self.interval_seconds)
        finally:
            self.health.stopped(self.component_name)
            self.logger.info("response worker stopped")
