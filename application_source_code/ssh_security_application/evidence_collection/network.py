"""SSH network packet metadata parsing, collection, validation, and storage."""

from __future__ import annotations

import logging
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, TextIO

from ssh_security_application.audit import AuditService
from ssh_security_application.config import NetworkSensorConfig
from ssh_security_application.constants import HealthState, ParseStatus
from ssh_security_application.evidence_collection.auth import (
    CollectorError,
)
from ssh_security_application.ip_validation import validate_ip_address
from ssh_security_application.models import HealthStatus, NetworkEvent, NetworkParseResult
from ssh_security_application.sqlite_data_storage.storage import (
    IPProfileRepository,
    NetworkEventRepository,
    ParserErrorRepository,
)
from ssh_security_application.ssh_brute_force_detection.deduplication import (
    EventDeduplicator,
)
from ssh_security_application.ssh_brute_force_detection.normalization import (
    generate_event_id,
    normalize_network_event,
)

# ---- Network packet parser ----
_TCPDUMP_LINE = re.compile(
    r"^(?P<timestamp>\d+(?:\.\d+)?)\s+"
    r"(?P<ip_label>IP6?)\s+"
    r"(?P<source>\S+)\.(?P<source_port>\d+)\s+>\s+"
    r"(?P<destination>\S+)\.(?P<destination_port>\d+):\s+"
    r"Flags\s+\[(?P<flags>[^\]]*)\](?:,.*)?$"
)


def parse_network_line(
    line: str,
    *,
    interface_name: str,
    ssh_port: int = 22,
    sensor_name: str = "network_tcpdump",
    collected_at: datetime | None = None,
) -> NetworkParseResult:
    """Parse one tcpdump metadata line without performing any I/O."""

    raw_message = line.rstrip("\r\n")
    match = _TCPDUMP_LINE.fullmatch(raw_message)
    if match is None:
        return NetworkParseResult(
            status=ParseStatus.MALFORMED,
            event=None,
            error_message="Record is not supported tcpdump TCP metadata",
        )

    try:
        event_time = _parse_epoch_timestamp(match.group("timestamp"))
        source_port = _parse_port(match.group("source_port"))
        destination_port = _parse_port(match.group("destination_port"))
    except (OSError, OverflowError, ValueError) as exc:
        return NetworkParseResult(
            status=ParseStatus.MALFORMED,
            event=None,
            error_message=str(exc),
        )

    if destination_port != ssh_port:
        return NetworkParseResult(
            status=ParseStatus.UNSUPPORTED,
            event=None,
            error_message=(
                f"Destination port {destination_port} is not configured SSH port {ssh_port}"
            ),
        )

    timestamp_collected = collected_at or datetime.now(timezone.utc)
    if timestamp_collected.tzinfo is None or timestamp_collected.utcoffset() is None:
        raise ValueError("collected_at must be timezone-aware")

    return NetworkParseResult(
        status=ParseStatus.PARSED,
        event=NetworkEvent(
            event_id=generate_event_id(),
            event_time=event_time,
            collected_at=timestamp_collected.astimezone(timezone.utc),
            source_ip=match.group("source"),
            destination_ip=match.group("destination"),
            source_port=source_port,
            destination_port=destination_port,
            tcp_flags=match.group("flags"),
            interface_name=interface_name,
            sensor_name=sensor_name,
            parse_status=ParseStatus.PARSED,
        ),
    )


def _parse_epoch_timestamp(value: str) -> datetime:
    seconds_text, separator, fraction = value.partition(".")
    seconds = int(seconds_text)
    microseconds = int((fraction + "000000")[:6]) if separator else 0
    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=microseconds)


def _parse_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"TCP port is outside 1-65535: {port}")
    return port


# ---- tcpdump collector ----
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
        self.logger = logging.getLogger("ssh_security_application.evidence_collection.network")

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


# ---- Network event ingestor ----
NETWORK_SENSOR_NAME = "network_tcpdump"


class NetworkIngestor:
    def __init__(
        self,
        *,
        network_events: NetworkEventRepository,
        parser_errors: ParserErrorRepository,
        ip_profiles: IPProfileRepository,
        audit: AuditService,
        interface_name: str,
        ssh_port: int,
        deduplicator: EventDeduplicator | None = None,
    ) -> None:
        self.network_events = network_events
        self.parser_errors = parser_errors
        self.ip_profiles = ip_profiles
        self.audit = audit
        self.interface_name = interface_name
        self.ssh_port = ssh_port
        self.deduplicator = deduplicator or EventDeduplicator()

    def process_line(self, line: str) -> NetworkEvent | None:
        parse_result = parse_network_line(
            line,
            interface_name=self.interface_name,
            ssh_port=self.ssh_port,
            sensor_name=NETWORK_SENSOR_NAME,
        )
        if parse_result.status is not ParseStatus.PARSED or parse_result.event is None:
            self._record_parser_error(
                line=line,
                message=parse_result.error_message or "Unknown parser failure",
                status=parse_result.status,
            )
            return None

        event = parse_result.event
        source_validation = validate_ip_address(event.source_ip)
        destination_validation = validate_ip_address(event.destination_ip)
        if not source_validation.is_valid or source_validation.normalized_ip is None:
            self._record_parser_error(
                line=line,
                message=source_validation.exclusion_reason or "Invalid source IP",
                status=ParseStatus.INVALID_IP,
            )
            return None
        if not destination_validation.is_valid or destination_validation.normalized_ip is None:
            self._record_parser_error(
                line=line,
                message=destination_validation.exclusion_reason or "Invalid destination IP",
                status=ParseStatus.INVALID_IP,
            )
            return None

        normalized = normalize_network_event(event)
        fingerprint = normalized.deduplication_key
        if fingerprint is None:
            raise ValueError("normalized network event has no fingerprint")
        if self.deduplicator.is_duplicate(fingerprint, observed_at=normalized.collected_at):
            return None
        if not self.network_events.insert(normalized):
            return None
        self.ip_profiles.observe_network(normalized, source_validation.category)
        return normalized

    def _record_parser_error(self, *, line: str, message: str, status: ParseStatus) -> None:
        error_id = self.parser_errors.record(
            sensor=NETWORK_SENSOR_NAME,
            raw_message=line.rstrip("\r\n"),
            error_message=message,
        )
        self.audit.record(
            component=NETWORK_SENSOR_NAME,
            action="parser_failure",
            target=error_id,
            result=status.value,
            details={"error": message},
        )
