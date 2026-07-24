from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ssh_guard.collectors.auth_parser import parse_authentication_line
from ssh_guard.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    ParseStatus,
)

PREFIX = "2026-07-24T08:00:01+00:00 ubuntu-lab sshd[1234]: "


@pytest.mark.parametrize(
    ("body", "event_type", "result", "username", "source_ip"),
    [
        (
            "Failed password for student from 192.168.56.20 port 50110 ssh2",
            AuthenticationEventType.FAILED_PASSWORD,
            AuthenticationResult.FAILURE,
            "student",
            "192.168.56.20",
        ),
        (
            "Failed password for invalid user oracle from 192.168.56.21 port 50111 ssh2",
            AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
            AuthenticationResult.FAILURE,
            "oracle",
            "192.168.56.21",
        ),
        (
            "Invalid user admin from 192.168.56.22 port 50112",
            AuthenticationEventType.INVALID_USER,
            AuthenticationResult.FAILURE,
            "admin",
            "192.168.56.22",
        ),
        (
            "Accepted password for student from 192.168.56.23 port 50113 ssh2",
            AuthenticationEventType.ACCEPTED_PASSWORD,
            AuthenticationResult.SUCCESS,
            "student",
            "192.168.56.23",
        ),
        (
            "Accepted publickey for analyst from 192.168.56.24 port 50114 "
            "ssh2: ED25519 SHA256:SANITIZED",
            AuthenticationEventType.ACCEPTED_PUBLIC_KEY,
            AuthenticationResult.SUCCESS,
            "analyst",
            "192.168.56.24",
        ),
        (
            "Connection closed by authenticating user root 192.168.56.25 port 50115 [preauth]",
            AuthenticationEventType.CONNECTION_CLOSED,
            AuthenticationResult.NEUTRAL,
            "root",
            "192.168.56.25",
        ),
        (
            "Connection closed by 192.168.56.26 port 50116 [preauth]",
            AuthenticationEventType.CONNECTION_CLOSED,
            AuthenticationResult.NEUTRAL,
            None,
            "192.168.56.26",
        ),
    ],
)
def test_supported_records(body, event_type, result, username, source_ip) -> None:
    collected = datetime(2026, 7, 24, 9, tzinfo=timezone.utc)

    parsed = parse_authentication_line(PREFIX + body, collected_at=collected)

    assert parsed.status is ParseStatus.PARSED
    assert parsed.error_message is None
    assert parsed.event is not None
    assert parsed.event.event_type is event_type
    assert parsed.event.authentication_result is result
    assert parsed.event.username == username
    assert parsed.event.source_ip == source_ip
    assert parsed.event.process_id == 1234
    assert parsed.event.event_time == datetime(2026, 7, 24, 8, 0, 1, tzinfo=timezone.utc)
    assert parsed.event.collected_at == collected


def test_offset_timestamp_is_normalized_to_utc() -> None:
    parsed = parse_authentication_line(
        "2026-07-24T10:30:00+0230 host sshd[1]: "
        "Failed password for root from 192.168.56.2 port 40000 ssh2"
    )

    assert parsed.event is not None
    assert parsed.event.event_time == datetime(2026, 7, 24, 8, 0, tzinfo=timezone.utc)


def test_unsupported_record_does_not_crash() -> None:
    parsed = parse_authentication_line(PREFIX + "Server listening on 0.0.0.0 port 22.")

    assert parsed.status is ParseStatus.UNSUPPORTED
    assert parsed.event is None


@pytest.mark.parametrize("line", ["", "not a journal record", "Jul 24 host sshd: no timestamp"])
def test_malformed_record_does_not_crash(line) -> None:
    parsed = parse_authentication_line(line)

    assert parsed.status is ParseStatus.MALFORMED
    assert parsed.event is None


def test_naive_collection_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        parse_authentication_line(
            PREFIX + "Failed password for root from 192.168.56.2 port 40000 ssh2",
            collected_at=datetime(2026, 7, 24),
        )
