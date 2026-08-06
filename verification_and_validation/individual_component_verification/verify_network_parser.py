from __future__ import annotations

from datetime import datetime, timezone

import pytest
from ssh_security_application.constants import ParseStatus
from ssh_security_application.evidence_collection.network import (
    parse_network_line,
)


def test_parse_ipv4_tcpdump_metadata() -> None:
    parsed = parse_network_line(
        "1784881200.123456 IP 192.168.56.40.52000 > 192.168.56.10.22: "
        "Flags [S], seq 1000, win 64240, length 0",
        interface_name="enp0s8",
    )

    assert parsed.status is ParseStatus.PARSED
    assert parsed.event is not None
    assert parsed.event.event_time == datetime(2026, 7, 24, 8, 20, 0, 123456, tzinfo=timezone.utc)
    assert parsed.event.source_ip == "192.168.56.40"
    assert parsed.event.destination_ip == "192.168.56.10"
    assert parsed.event.source_port == 52000
    assert parsed.event.destination_port == 22
    assert parsed.event.tcp_flags == "S"
    assert parsed.event.interface_name == "enp0s8"


def test_parse_ipv6_tcpdump_metadata() -> None:
    parsed = parse_network_line(
        "1784881200.000001 IP6 2001:4860:4860::8888.52000 > "
        "2001:4860:4860::8844.22: Flags [S.], seq 1, ack 2, length 0",
        interface_name="enp0s8",
    )

    assert parsed.event is not None
    assert parsed.event.source_ip == "2001:4860:4860::8888"
    assert parsed.event.tcp_flags == "S."


def test_non_ssh_destination_is_unsupported() -> None:
    parsed = parse_network_line(
        "1784881200.000001 IP 192.168.56.40.52000 > 192.168.56.10.80: Flags [S], seq 1, length 0",
        interface_name="enp0s8",
    )

    assert parsed.status is ParseStatus.UNSUPPORTED
    assert parsed.event is None
    assert "not configured SSH port" in (parsed.error_message or "")


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not tcpdump",
        "1784881200 IP 192.168.56.40 > 192.168.56.10: tcp 0",
        "1784881200 IP 192.168.56.40.70000 > 192.168.56.10.22: Flags [S]",
        "999999999999999999999 IP 192.168.56.40.52000 > 192.168.56.10.22: Flags [S]",
    ],
)
def test_malformed_records_do_not_crash(line) -> None:
    parsed = parse_network_line(line, interface_name="enp0s8")

    assert parsed.status is ParseStatus.MALFORMED
    assert parsed.event is None


def test_naive_collected_at_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        parse_network_line(
            "1784881200.000001 IP 192.168.56.40.52000 > 192.168.56.10.22: Flags [S]",
            interface_name="enp0s8",
            collected_at=datetime(2026, 7, 24),
        )
