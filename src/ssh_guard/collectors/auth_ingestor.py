"""Persist parsed and validated authentication evidence."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from ssh_guard.audit import AuditService
from ssh_guard.collectors.auth_parser import parse_authentication_line
from ssh_guard.constants import ParseStatus
from ssh_guard.core.deduplication import EventDeduplicator
from ssh_guard.core.ip_validation import validate_ip_address
from ssh_guard.core.normalization import normalize_authentication_event
from ssh_guard.db.repositories import (
    AuthenticationEventRepository,
    IPProfileRepository,
    ParserErrorRepository,
)
from ssh_guard.models import AuthenticationEvent

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
