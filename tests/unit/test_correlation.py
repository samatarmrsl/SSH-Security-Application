from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from ssh_guard.constants import (
    AuthenticationEventType,
    AuthenticationResult,
    ParseStatus,
)
from ssh_guard.core.correlation import correlate_events
from ssh_guard.models import AuthenticationEvent, NetworkEvent


def auth_event(
    event_id: str,
    seconds: int,
    username: str,
    event_type: AuthenticationEventType,
    result: AuthenticationResult,
) -> AuthenticationEvent:
    event_time = datetime(2026, 7, 24, 8, 20, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return AuthenticationEvent(
        event_id=event_id,
        event_time=event_time,
        collected_at=event_time,
        source_ip="192.168.56.40",
        username=username,
        event_type=event_type,
        authentication_result=result,
        process_id=100 + seconds,
        raw_message=event_id,
        parse_status=ParseStatus.PARSED,
    )


def network_event(event_id: str, seconds: int) -> NetworkEvent:
    event_time = datetime(2026, 7, 24, 8, 20, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return NetworkEvent(
        event_id=event_id,
        event_time=event_time,
        collected_at=event_time,
        source_ip="192.168.56.40",
        destination_ip="192.168.56.10",
        source_port=50000 + seconds,
        destination_port=22,
        tcp_flags="S",
        interface_name="enp0s8",
        sensor_name="network_tcpdump",
        parse_status=ParseStatus.PARSED,
    )


def test_correlation_calculates_required_values_and_evidence_links() -> None:
    start = datetime(2026, 7, 24, 8, 20, tzinfo=timezone.utc)
    auth_events = [
        auth_event(
            "a1",
            0,
            "root",
            AuthenticationEventType.FAILED_PASSWORD,
            AuthenticationResult.FAILURE,
        ),
        auth_event(
            "a2",
            10,
            "admin",
            AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
            AuthenticationResult.FAILURE,
        ),
        auth_event(
            "a3",
            20,
            "admin",
            AuthenticationEventType.INVALID_USER,
            AuthenticationResult.FAILURE,
        ),
        auth_event(
            "a4",
            30,
            "student",
            AuthenticationEventType.ACCEPTED_PASSWORD,
            AuthenticationResult.SUCCESS,
        ),
    ]
    network_events = [network_event("n1", 0), network_event("n2", 10)]

    result = correlate_events(
        source_ip="192.168.56.40",
        auth_events=auth_events,
        network_events=network_events,
        window_start=start,
        window_end=start + timedelta(minutes=5),
        window_seconds=300,
        recent_success=True,
        previous_detection_count=2,
        previous_block_count=1,
        allowlisted=True,
    )

    assert result.failed_count == 2
    assert result.successful_count == 1
    assert result.invalid_user_count == 2
    assert result.unique_usernames == 2
    assert result.network_connection_count == 2
    assert result.attempt_rate == 0.4
    assert result.recent_success is True
    assert result.previous_detection_count == 2
    assert result.previous_block_count == 1
    assert result.allowlisted is True
    assert result.auth_event_ids == ("a1", "a2", "a3", "a4")
    assert result.network_event_ids == ("n1", "n2")
    assert result.first_event_time == start
    assert result.last_event_time == start + timedelta(seconds=30)


def test_events_outside_window_or_from_other_ip_are_excluded() -> None:
    start = datetime(2026, 7, 24, 8, 20, tzinfo=timezone.utc)
    outside = auth_event(
        "outside",
        301,
        "root",
        AuthenticationEventType.FAILED_PASSWORD,
        AuthenticationResult.FAILURE,
    )
    other = auth_event(
        "other",
        10,
        "root",
        AuthenticationEventType.FAILED_PASSWORD,
        AuthenticationResult.FAILURE,
    )
    other = replace(other, source_ip="192.168.56.99")

    result = correlate_events(
        source_ip="192.168.56.40",
        auth_events=[outside, other],
        network_events=[],
        window_start=start,
        window_end=start + timedelta(minutes=5),
        window_seconds=300,
    )

    assert result.failed_count == 0
    assert result.auth_event_ids == ()
