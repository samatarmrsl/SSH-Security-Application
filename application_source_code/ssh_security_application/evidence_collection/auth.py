"""Authentication log parsing, collection, validation, and storage."""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Pattern, TextIO

from ssh_security_application.audit import AuditService
from ssh_security_application.config import AuthenticationSensorConfig
from ssh_security_application.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    HealthState,
    ParseStatus,
)
from ssh_security_application.ip_validation import validate_ip_address
from ssh_security_application.models import (
    AuthenticationEvent,
    AuthenticationParseResult,
    HealthStatus,
)
from ssh_security_application.sqlite_data_storage.storage import (
    AuthenticationEventRepository,
    IPProfileRepository,
    ParserErrorRepository,
)
from ssh_security_application.ssh_brute_force_detection.deduplication import (
    EventDeduplicator,
)
from ssh_security_application.ssh_brute_force_detection.normalization import (
    normalize_authentication_event,
)

# ---- Authentication parser ----
_JOURNAL_PREFIX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"\S+\s+sshd\[(?P<process_id>\d+)\]:\s+"
    r"(?P<body>.+)$"
)


@dataclass(frozen=True)
class _MessagePattern:
    expression: Pattern[str]
    event_type: AuthenticationEventType
    result: AuthenticationResult


_MESSAGE_PATTERNS = (
    _MessagePattern(
        re.compile(
            r"^Failed password for invalid user (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
        AuthenticationResult.FAILURE,
    ),
    _MessagePattern(
        re.compile(
            r"^Failed password for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.FAILED_PASSWORD,
        AuthenticationResult.FAILURE,
    ),
    _MessagePattern(
        re.compile(
            r"^Invalid user (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.INVALID_USER,
        AuthenticationResult.FAILURE,
    ),
    _MessagePattern(
        re.compile(
            r"^Accepted password for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.ACCEPTED_PASSWORD,
        AuthenticationResult.SUCCESS,
    ),
    _MessagePattern(
        re.compile(
            r"^Accepted publickey for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.ACCEPTED_PUBLIC_KEY,
        AuthenticationResult.SUCCESS,
    ),
    _MessagePattern(
        re.compile(
            r"^Connection closed by authenticating user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.CONNECTION_CLOSED,
        AuthenticationResult.NEUTRAL,
    ),
    _MessagePattern(
        re.compile(
            r"^Connection closed by invalid user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.CONNECTION_CLOSED,
        AuthenticationResult.NEUTRAL,
    ),
    _MessagePattern(
        re.compile(
            r"^Connection closed by (?P<username>\S+) "
            r"(?P<source_ip>\S+) port \d+(?: .*)?$"
        ),
        AuthenticationEventType.CONNECTION_CLOSED,
        AuthenticationResult.NEUTRAL,
    ),
    _MessagePattern(
        re.compile(r"^Connection closed by (?P<source_ip>\S+) port \d+(?: .*)?$"),
        AuthenticationEventType.CONNECTION_CLOSED,
        AuthenticationResult.NEUTRAL,
    ),
)


def parse_authentication_line(
    line: str,
    *,
    collected_at: datetime | None = None,
) -> AuthenticationParseResult:
    """Parse one journal line without performing I/O or database writes."""

    raw_message = line.rstrip("\r\n")
    prefix_match = _JOURNAL_PREFIX.fullmatch(raw_message)
    if prefix_match is None:
        return AuthenticationParseResult(
            status=ParseStatus.MALFORMED,
            event=None,
            error_message="Record is not an sshd short-ISO journal line",
        )

    try:
        event_time = _parse_timestamp(prefix_match.group("timestamp"))
    except ValueError as exc:
        return AuthenticationParseResult(
            status=ParseStatus.MALFORMED,
            event=None,
            error_message=f"Record contains an invalid timestamp: {exc}",
        )

    body = prefix_match.group("body")
    for candidate in _MESSAGE_PATTERNS:
        message_match = candidate.expression.fullmatch(body)
        if message_match is None:
            continue
        groups = message_match.groupdict()
        timestamp_collected = collected_at or datetime.now(timezone.utc)
        if timestamp_collected.tzinfo is None or timestamp_collected.utcoffset() is None:
            raise ValueError("collected_at must be timezone-aware")
        event = AuthenticationEvent(
            event_id=str(uuid.uuid4()),
            event_time=event_time,
            collected_at=timestamp_collected.astimezone(timezone.utc),
            source_ip=groups["source_ip"],
            username=groups.get("username"),
            event_type=candidate.event_type,
            authentication_result=candidate.result,
            process_id=int(prefix_match.group("process_id")),
            raw_message=raw_message,
            parse_status=ParseStatus.PARSED,
        )
        return AuthenticationParseResult(status=ParseStatus.PARSED, event=event)

    return AuthenticationParseResult(
        status=ParseStatus.UNSUPPORTED,
        event=None,
        error_message="OpenSSH record type is not supported",
    )


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


# ---- OpenSSH journal collector ----
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
        self.logger = logging.getLogger("ssh_security_application.evidence_collection.auth")

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


# ---- Authentication event ingestor ----
AUTH_SENSOR_NAME = "auth_journal"


class AuthenticationIngestor:
    """Turn raw journal lines into normalized database evidence."""

    def __init__(
        self,
        *,
        auth_events: AuthenticationEventRepository,
        parser_errors: ParserErrorRepository,
        ip_profiles: IPProfileRepository,
        audit: AuditService,
        protected_addresses: Iterable[str] = (),
        deduplicator: EventDeduplicator | None = None,
    ) -> None:
        self.auth_events = auth_events
        self.parser_errors = parser_errors
        self.ip_profiles = ip_profiles
        self.audit = audit
        self.protected_addresses = tuple(protected_addresses)
        self.deduplicator = deduplicator or EventDeduplicator()

    def process_line(self, line: str) -> AuthenticationEvent | None:
        parse_result = parse_authentication_line(line)
        if parse_result.status is not ParseStatus.PARSED or parse_result.event is None:
            self._record_parser_error(
                line=line,
                message=parse_result.error_message or "Unknown parser failure",
                status=parse_result.status,
            )
            return None

        event = parse_result.event
        validation = validate_ip_address(
            event.source_ip,
            protected_addresses=self.protected_addresses,
        )
        if not validation.is_valid or validation.normalized_ip is None:
            self._record_parser_error(
                line=line,
                message=validation.exclusion_reason or "Invalid source IP",
                status=ParseStatus.INVALID_IP,
            )
            return None

        normalized_event = normalize_authentication_event(
            replace(event, source_ip=validation.normalized_ip)
        )
        fingerprint = normalized_event.deduplication_key
        if fingerprint is None:
            raise ValueError("normalized authentication event has no fingerprint")
        if self.deduplicator.is_duplicate(
            fingerprint,
            observed_at=normalized_event.collected_at,
        ):
            return None
        if not self.auth_events.insert(normalized_event):
            return None
        self.ip_profiles.observe_authentication(normalized_event, validation.category)
        return normalized_event

    def _record_parser_error(self, *, line: str, message: str, status: ParseStatus) -> None:
        error_id = self.parser_errors.record(
            sensor=AUTH_SENSOR_NAME,
            raw_message=line.rstrip("\r\n"),
            error_message=message,
        )
        self.audit.record(
            component=AUTH_SENSOR_NAME,
            action="parser_failure",
            target=error_id,
            result=status.value,
            details={"error": message},
        )
