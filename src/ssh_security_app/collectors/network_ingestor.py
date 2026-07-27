"""Validate, deduplicate, and persist TCP/22 metadata."""

from __future__ import annotations

from ssh_security_app.audit import AuditService
from ssh_security_app.collectors.network_parser import parse_network_line
from ssh_security_app.constants import ParseStatus
from ssh_security_app.core.deduplication import EventDeduplicator
from ssh_security_app.core.ip_validation import validate_ip_address
from ssh_security_app.core.normalization import normalize_network_event
from ssh_security_app.db.repositories import (
    IPProfileRepository,
    NetworkEventRepository,
    ParserErrorRepository,
)
from ssh_security_app.models import NetworkEvent

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
