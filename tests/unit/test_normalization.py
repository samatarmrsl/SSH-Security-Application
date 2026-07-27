from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ssh_security_app.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    ParseStatus,
)
from ssh_security_app.core.deduplication import EventDeduplicator
from ssh_security_app.core.normalization import (
    ensure_utc,
    normalize_authentication_event,
)
from ssh_security_app.models import AuthenticationEvent


def auth_event(event_id: str = "event-1") -> AuthenticationEvent:
    return AuthenticationEvent(
        event_id=event_id,
        event_time=datetime(2026, 7, 24, 10, tzinfo=timezone(timedelta(hours=2))),
        collected_at=datetime(2026, 7, 24, 8, 1, tzinfo=timezone.utc),
        source_ip="192.168.56.20",
        username="root",
        event_type=AuthenticationEventType.FAILED_PASSWORD,
        authentication_result=AuthenticationResult.FAILURE,
        process_id=100,
        raw_message="sanitized message",
        parse_status=ParseStatus.PARSED,
    )


def test_auth_normalization_is_stable_across_event_ids() -> None:
    first = normalize_authentication_event(auth_event("one"))
    second = normalize_authentication_event(auth_event("two"))

    assert first.event_time == datetime(2026, 7, 24, 8, tzinfo=timezone.utc)
    assert first.deduplication_key == second.deduplication_key


def test_ensure_utc_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ensure_utc(datetime(2026, 7, 24))


def test_short_window_deduplicator_expires_entries() -> None:
    deduplicator = EventDeduplicator(window_seconds=5)
    start = datetime(2026, 7, 24, 8, tzinfo=timezone.utc)

    assert deduplicator.is_duplicate("fingerprint", observed_at=start) is False
    assert (
        deduplicator.is_duplicate(
            "fingerprint",
            observed_at=start + timedelta(seconds=2),
        )
        is True
    )
    assert (
        deduplicator.is_duplicate(
            "fingerprint",
            observed_at=start + timedelta(seconds=10),
        )
        is False
    )


def test_invalid_duplicate_window_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one second"):
        EventDeduplicator(0)
