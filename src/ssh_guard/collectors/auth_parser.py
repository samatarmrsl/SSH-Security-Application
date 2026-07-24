"""Pure parser for OpenSSH journal messages in short-ISO format."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Pattern

from ssh_guard.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    ParseStatus,
)
from ssh_guard.models import AuthenticationEvent, AuthenticationParseResult

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
