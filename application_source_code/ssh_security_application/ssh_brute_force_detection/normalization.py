"""UTC, IP, and stable-event normalization."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from ssh_security_application.models import AuthenticationEvent, NetworkEvent


def ensure_utc(value: datetime) -> datetime:
    """Return an aware datetime in UTC and reject ambiguous naive values."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def normalize_ip(value: str) -> str:
    """Return the canonical representation of a valid IP address."""

    return str(ipaddress.ip_address(value.strip()))


def generate_event_id() -> str:
    return str(uuid.uuid4())


def authentication_fingerprint(event: AuthenticationEvent) -> str:
    return _fingerprint(
        {
            "sensor": "auth_journal",
            "event_time": ensure_utc(event.event_time).isoformat(),
            "source_ip": normalize_ip(event.source_ip),
            "username": event.username,
            "event_type": event.event_type.value,
            "raw_message_sha256": hashlib.sha256(event.raw_message.encode("utf-8")).hexdigest(),
        }
    )


def network_fingerprint(event: NetworkEvent) -> str:
    return _fingerprint(
        {
            "sensor": event.sensor_name,
            "event_time": ensure_utc(event.event_time).isoformat(),
            "source_ip": normalize_ip(event.source_ip),
            "destination_ip": normalize_ip(event.destination_ip),
            "source_port": event.source_port,
            "destination_port": event.destination_port,
            "tcp_flags": event.tcp_flags,
            "interface_name": event.interface_name,
        }
    )


def normalize_authentication_event(event: AuthenticationEvent) -> AuthenticationEvent:
    normalized = replace(
        event,
        event_time=ensure_utc(event.event_time),
        collected_at=ensure_utc(event.collected_at),
        source_ip=normalize_ip(event.source_ip),
    )
    return replace(normalized, deduplication_key=authentication_fingerprint(normalized))


def normalize_network_event(event: NetworkEvent) -> NetworkEvent:
    normalized = replace(
        event,
        event_time=ensure_utc(event.event_time),
        collected_at=ensure_utc(event.collected_at),
        source_ip=normalize_ip(event.source_ip),
        destination_ip=normalize_ip(event.destination_ip),
    )
    return replace(normalized, deduplication_key=network_fingerprint(normalized))


def evidence_fingerprint(
    source_ip: str,
    auth_event_ids: tuple[str, ...],
    network_event_ids: tuple[str, ...],
) -> str:
    return _fingerprint(
        {
            "source_ip": normalize_ip(source_ip),
            "auth_event_ids": sorted(auth_event_ids),
            "network_event_ids": sorted(network_event_ids),
        }
    )


def _fingerprint(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
