"""OpenSSH systemd-journal and fixture-file collector."""

from __future__ import annotations

import logging
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, TextIO

from ssh_security_app.config import AuthenticationSensorConfig
from ssh_security_app.constants import HealthState
from ssh_security_app.models import AuthenticationEvent, HealthStatus

EventCallback = Callable[[str], Optional[AuthenticationEvent]]
HealthCallback = Callable[[HealthStatus], None]


class CollectorError(RuntimeError):
    """Raised when journal collection cannot continue."""


class AuthenticationJournalCollector:
    """Collect OpenSSH records without invoking a shell."""

    component_name = "authentication_sensor"

    def __init__(
        self,
        config: AuthenticationSensorConfig,
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
        self.logger = logging.getLogger("ssh_security_app.collectors.auth_journal")

    def build_command(self, *, follow: bool, since: str | None = None) -> list[str]:
        command = [
            self.config.journalctl_path,
            "-u",
            self.config.systemd_unit,
            "SYSLOG_IDENTIFIER=sshd",
            "-o",
            "short-iso",
            "--no-pager",
            "--quiet",
        ]
        if since:
            command.extend(["--since", since])
        if follow:
            if not since:
                command.extend(["--lines", "0"])
            command.append("-f")
        return command

    def collect_once(self, *, since: str | None = None) -> int:
        """Read current matching journal records and return the processed line count."""

        if not self.config.enabled:
            self._report(HealthState.STOPPED, details={"reason": "disabled"})
            return 0
        effective_since = since or f"-{self.config.lookback_minutes} minutes"
        command = self.build_command(follow=False, since=effective_since)
        self._report(HealthState.HEALTHY, details={"mode": "one-shot", "command": command})
        process = self._start_process(command)
        stdout, stderr = process.communicate()
        self._clear_process(process)
        if process.returncode != 0:
            message = stderr.strip() or f"journalctl exited with status {process.returncode}"
            self._report(HealthState.FAILED, error=message, details={"mode": "one-shot"})
            raise CollectorError(message)
        count = self._process_text(stdout)
        self._report(
            HealthState.HEALTHY,
            details={"mode": "one-shot", "records_processed": count},
        )
        return count

    def collect_fixture(self, fixture_path: str | Path) -> int:
        """Read sanitized fixture records without starting a subprocess."""

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

    def follow(self, *, since: str | None = None) -> int:
        """Follow the journal until stop() is called or journalctl exits."""

        if not self.config.enabled:
            self._report(HealthState.STOPPED, details={"reason": "disabled"})
            return 0
        self._stop_event.clear()
        command = self.build_command(follow=True, since=since)
        self._report(HealthState.HEALTHY, details={"mode": "follow", "command": command})
        process = self._start_process(command)
        if process.stdout is None or process.stderr is None:
            self._clear_process(process)
            raise CollectorError("journalctl pipes were not created")

        stderr_lines: list[str] = []
        stderr_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_lines),
            name="ssh-security-app-journal-stderr",
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

        stderr = "".join(stderr_lines).strip()
        if process.returncode not in (0, -15) and not self._stop_event.is_set():
            message = stderr or f"journalctl exited with status {process.returncode}"
            self._report(HealthState.FAILED, error=message, details={"mode": "follow"})
            raise CollectorError(message)
        self._report(HealthState.STOPPED, details={"mode": "follow", "records_processed": count})
        return count

    def start_follow(self, *, since: str | None = None) -> threading.Thread:
        """Start follow mode in a background thread."""

        if self._thread and self._thread.is_alive():
            raise CollectorError("authentication collector is already running")
        self._thread = threading.Thread(
            target=self.follow,
            kwargs={"since": since},
            name="ssh-security-app-auth-journal",
            daemon=True,
        )
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        """Request shutdown and terminate a blocked journalctl process."""

        self._stop_event.set()
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=6)

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
            message = f"could not start journalctl: {exc}"
            self._report(HealthState.FAILED, error=message)
            raise CollectorError(message) from exc
        with self._lock:
            self._process = process
        return process

    def _clear_process(self, process: subprocess.Popen[str]) -> None:
        with self._lock:
            if self._process is process:
                self._process = None

    def _process_text(self, value: str) -> int:
        count = 0
        for line in value.splitlines():
            if line.strip():
                self.on_line(line)
                count += 1
        return count

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
        log_method("authentication sensor status=%s details=%s error=%s", status, details, error)


def _drain_stream(stream: TextIO, output: list[str]) -> None:
    for line in stream:
        output.append(line)
