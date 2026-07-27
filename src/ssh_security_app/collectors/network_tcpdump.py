"""Filtered tcpdump collector for inbound SSH connection metadata."""

from __future__ import annotations

import logging
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, TextIO

from ssh_security_app.collectors.auth_journal import CollectorError
from ssh_security_app.config import NetworkSensorConfig
from ssh_security_app.constants import HealthState
from ssh_security_app.models import HealthStatus, NetworkEvent

EventCallback = Callable[[str], Optional[NetworkEvent]]
HealthCallback = Callable[[HealthStatus], None]


class NetworkTcpdumpCollector:
    component_name = "network_sensor"

    def __init__(
        self,
        config: NetworkSensorConfig,
        *,
        on_line: EventCallback,
        on_health: HealthCallback | None = None,
    ) -> None:
        self.config = config
        self.on_line = on_line
        self.on_health = on_health
        self._stop_event = threading.Event()
        self._process: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.logger = logging.getLogger("ssh_security_app.collectors.network_tcpdump")

    def build_command(self) -> list[str]:
        return [
            self.config.tcpdump_path,
            "-i",
            self.config.interface,
            "-nn",
            "-l",
            "-tt",
            "-s",
            str(self.config.snapshot_length_bytes),
            "tcp",
            "dst",
            "port",
            str(self.config.ssh_port),
        ]

    def collect_fixture(self, fixture_path: str | Path) -> int:
        path = Path(fixture_path)
        self._report(HealthState.HEALTHY, details={"mode": "fixture", "path": str(path)})
        try:
            with path.open(encoding="utf-8") as handle:
                count = self._process_stream(handle)
        except (OSError, UnicodeError) as exc:
            message = f"could not read fixture {path}: {exc}"
            self._report(HealthState.FAILED, error=message, details={"mode": "fixture"})
            raise CollectorError(message) from exc
        self._report(
            HealthState.HEALTHY,
            details={"mode": "fixture", "records_processed": count},
        )
        return count

    def follow(self) -> int:
        if not self.config.enabled:
            self._report(HealthState.STOPPED, details={"reason": "disabled"})
            return 0

        self._stop_event.clear()
        total_count = 0
        failures = 0
        while not self._stop_event.is_set():
            try:
                count, return_code, stderr = self._capture_once()
                total_count += count
                if self._stop_event.is_set():
                    break
                message = stderr or f"tcpdump exited unexpectedly with status {return_code}"
            except CollectorError as exc:
                message = str(exc)

            failures += 1
            if failures > self.config.max_restart_attempts:
                self._report(
                    HealthState.FAILED,
                    error=message,
                    details={"mode": "follow", "restart_attempts": failures - 1},
                )
                raise CollectorError(message)

            self._report(
                HealthState.DEGRADED,
                error=message,
                details={
                    "mode": "follow",
                    "restart_attempt": failures,
                    "restart_delay_seconds": self.config.restart_delay_seconds,
                },
            )
            if self._stop_event.wait(self.config.restart_delay_seconds):
                break

        self._report(
            HealthState.STOPPED,
            details={"mode": "follow", "records_processed": total_count},
        )
        return total_count

    def start_follow(self) -> threading.Thread:
        if self._thread and self._thread.is_alive():
            raise CollectorError("network collector is already running")
        self._thread = threading.Thread(
            target=self.follow,
            name="ssh-security-app-network-tcpdump",
            daemon=True,
        )
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=6)

    def _capture_once(self) -> tuple[int, int, str]:
        command = self.build_command()
        self._report(HealthState.HEALTHY, details={"mode": "follow", "command": command})
        process = self._start_process(command)
        if process.stdout is None or process.stderr is None:
            self._clear_process(process)
            raise CollectorError("tcpdump pipes were not created")

        stderr_lines: list[str] = []
        stderr_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_lines),
            name="ssh-security-app-tcpdump-stderr",
            daemon=True,
        )
        stderr_thread.start()

        count = 0
        try:
            for line in process.stdout:
                if self._stop_event.is_set():
                    break
                if line.strip():
                    self.on_line(line)
                    count += 1
        finally:
            if self._stop_event.is_set() and process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stderr_thread.join(timeout=1)
            self._clear_process(process)
        return count, int(process.returncode or 0), "".join(stderr_lines).strip()

    def _start_process(self, command: list[str]) -> subprocess.Popen[str]:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
        except OSError as exc:
            raise CollectorError(f"could not start tcpdump: {exc}") from exc
        with self._lock:
            self._process = process
        return process

    def _clear_process(self, process: subprocess.Popen[str]) -> None:
        with self._lock:
            if self._process is process:
                self._process = None

    def _process_stream(self, stream: TextIO) -> int:
        count = 0
        for line in stream:
            if self._stop_event.is_set():
                break
            if line.strip():
                self.on_line(line)
                count += 1
        return count

    def _report(
        self,
        status: HealthState,
        *,
        error: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        health = HealthStatus(
            component=self.component_name,
            status=status,
            last_success=datetime.now(timezone.utc) if status is HealthState.HEALTHY else None,
            last_error=error,
            details=details or {},
        )
        if self.on_health:
            self.on_health(health)
        log_method = self.logger.error if status is HealthState.FAILED else self.logger.info
        log_method("network sensor status=%s details=%s error=%s", status, details, error)


def _drain_stream(stream: TextIO, output: list[str]) -> None:
    for line in stream:
        output.append(line)
