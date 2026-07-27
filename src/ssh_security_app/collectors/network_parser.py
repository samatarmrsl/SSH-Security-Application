"""Pure parser for tcpdump TCP/22 metadata emitted with epoch timestamps."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ssh_security_app.constants import ParseStatus
from ssh_security_app.core.normalization import generate_event_id
from ssh_security_app.models import NetworkEvent, NetworkParseResult

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
