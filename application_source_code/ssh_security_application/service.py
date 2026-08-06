"""Coordinate long-running collectors, detection, and response components."""

from __future__ import annotations

import logging
from collections.abc import Callable
from threading import Event, Thread
from typing import Protocol

from ssh_security_application.audit import AuditService
from ssh_security_application.health import HealthMonitor


class StoppableCollector(Protocol):
    def follow(self, **kwargs: object) -> int: ...

    def stop(self) -> None: ...


class DetectionRunner(Protocol):
    def run_all(self) -> list[object]: ...


class ResponseRunner(Protocol):
    def run(self, stop_event: Event) -> None: ...


class ApplicationController:
    """Own component threads and provide one clean shutdown boundary."""

    component_name = "application_controller"

    def __init__(
        self,
        *,
        authentication_collector: StoppableCollector,
        network_collector: StoppableCollector,
        detector: DetectionRunner,
        response_worker: ResponseRunner | None,
        audit: AuditService,
        health: HealthMonitor,
        detection_interval_seconds: int = 30,
    ) -> None:
        if detection_interval_seconds < 1:
            raise ValueError("detection interval must be positive")
        self.authentication_collector = authentication_collector
        self.network_collector = network_collector
        self.detector = detector
        self.response_worker = response_worker
        self.audit = audit
        self.health = health
        self.detection_interval_seconds = detection_interval_seconds
        self.logger = logging.getLogger("ssh_security_application.service")

    def run(self, stop_event: Event) -> None:
        components: list[tuple[str, Callable[[], None]]] = [
            (
                "authentication_sensor",
                lambda: self.authentication_collector.follow(),
            ),
            ("network_sensor", lambda: self.network_collector.follow()),
            ("correlation_engine", lambda: self._run_detector(stop_event)),
        ]
        if self.response_worker is not None:
            components.append(("response_worker", lambda: self.response_worker.run(stop_event)))
        threads = [
            Thread(
                target=self._guard_component,
                args=(name, target, stop_event),
                name=f"ssh-security-app-{name}",
                daemon=True,
            )
            for name, target in components
        ]
        self.audit.record(
            component=self.component_name,
            action="application_startup",
            result="success",
            details={"components": [name for name, _target in components]},
        )
        self.health.healthy(
            self.component_name,
            components=[name for name, _target in components],
        )
        for thread in threads:
            thread.start()

        try:
            while not stop_event.wait(0.5):
                if any(not thread.is_alive() for thread in threads):
                    self.logger.error("a required component exited; stopping application")
                    stop_event.set()
        finally:
            stop_event.set()
            self.authentication_collector.stop()
            self.network_collector.stop()
            for thread in threads:
                thread.join(timeout=10)
            still_running = [thread.name for thread in threads if thread.is_alive()]
            if still_running:
                self.health.degraded(
                    self.component_name,
                    "one or more component threads did not stop in time",
                    threads=still_running,
                )
            else:
                self.health.stopped(self.component_name)
            self.audit.record(
                component=self.component_name,
                action="application_shutdown",
                result="degraded" if still_running else "success",
                details={"threads_still_running": still_running},
            )

    def _run_detector(self, stop_event: Event) -> None:
        while not stop_event.is_set():
            detections = self.detector.run_all()
            self.health.healthy(
                "correlation_engine",
                detections_created=len(detections),
            )
            stop_event.wait(self.detection_interval_seconds)

    def _guard_component(
        self,
        name: str,
        target: Callable[[], None],
        stop_event: Event,
    ) -> None:
        try:
            target()
        except Exception as exc:
            self.logger.exception("component %s failed", name)
            self.health.failed(name, str(exc))
            self.audit.record(
                component=name,
                action="component_failure",
                result="failure",
                details={"error": str(exc)},
            )
        finally:
            stop_event.set()
