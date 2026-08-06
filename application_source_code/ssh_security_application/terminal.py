"""Readable terminal output for the SSH Security Application."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ssh_security_application.config import Settings
from ssh_security_application.models import (
    AuthenticationEvent,
    BlockRecord,
    BlockResponse,
    Detection,
    NetworkEvent,
)


class TerminalInterface:
    """Print the operator-facing terminal view."""

    def print_monitor_startup(self, settings: Settings, *, firewall_ready: bool) -> None:
        protected = ", ".join(settings.network_sensor.protected_ipv4_addresses) or "not configured"
        print("SSH SECURITY APPLICATION")
        print(f"Mode: {settings.response.mode.value.upper()}")
        print(f"Protected service: {protected}:{settings.network_sensor.ssh_port}")
        print(f"Authentication source: {settings.authentication_sensor.systemd_unit}")
        print(f"Network interface: {settings.network_sensor.interface}")
        print(f"Firewall chain: {settings.response.iptables_chain}")
        print(f"Firewall ready: {'YES' if firewall_ready else 'NO'}")
        print("Press Ctrl+C to stop monitoring.")
        print("=" * 80)

    def print_auth_event(self, event: AuthenticationEvent, *, failures_in_window: int) -> None:
        print(f"[{_clock()}] AUTH     {event.event_type.value.replace('_', ' ')}")
        print(f"                     Source IP: {event.source_ip}")
        if event.username:
            print(f"                     Username: {event.username}")
        print(f"                     Result: {event.authentication_result.value}")
        print(f"                     Failures in window: {failures_in_window}")

    def print_network_event(self, event: NetworkEvent) -> None:
        print(f"[{_clock()}] NETWORK  TCP/{event.destination_port} metadata")
        print(f"                     Source IP: {event.source_ip}:{event.source_port}")
        print(f"                     Destination: {event.destination_ip}:{event.destination_port}")
        print(f"                     Interface: {event.interface_name}")
        print(f"                     TCP flags: {event.tcp_flags}")

    def print_detection(
        self,
        detection: Detection,
        *,
        block_response: BlockResponse | None,
        block_duration_seconds: int,
        exact_rule: str | None,
        input_jump_rule: str | None = None,
        source_profile: dict[str, Any] | None = None,
        recent_auth_events: list[AuthenticationEvent] | None = None,
        recent_network_events: list[NetworkEvent] | None = None,
    ) -> None:
        print(f"[{_clock()}] ALERT    Possible SSH brute-force activity")
        print(f"                     Source IP: {detection.source_ip}")
        print(
            "                     Window: "
            f"{_display_time(detection.window_start)} -> {_display_time(detection.window_end)}"
        )
        print(f"                     Failures: {detection.failed_count}")
        print(f"                     Unique usernames: {detection.unique_usernames}")
        print(f"                     TCP/22 connections: {detection.network_connection_count}")
        print(f"                     Attempts per minute: {detection.attempt_rate}")
        self._print_source_profile(
            source_profile=source_profile,
            recent_auth_events=recent_auth_events or [],
            recent_network_events=recent_network_events or [],
        )
        print(f"[{_clock()}] SCORE    Risk score: {detection.risk_score}/100")
        print(f"                     Classification: {detection.classification.value.upper()}")
        for name, points in sorted(detection.risk_breakdown.items()):
            print(f"                     {name.replace('_', ' ').title()}: {points}")
        print(f"[{_clock()}] DECISION {detection.decision.value}")
        print(f"                     Reason: {detection.decision_reason}")
        if detection.decision.value == "WOULD_BLOCK":
            print(f"                     Duration: {block_duration_seconds} seconds")
            print("                     Firewall changed: NO")
        if block_response is not None:
            label = "BLOCK" if block_response.success else "ERROR"
            print(f"[{_clock()}] {label:<8} {block_response.message}")
            if block_response.block is not None:
                print(f"                     Source IP: {block_response.block.source_ip}")
                expires_at = _display_time(block_response.block.expires_at)
                print(f"                     Expires: {expires_at}")
            if input_jump_rule:
                print(f"[{_clock()}] RULE     INPUT jump: {input_jump_rule}")
            if exact_rule:
                print(f"[{_clock()}] RULE     DROP rule: {exact_rule}")

    def print_unblock(self, block: BlockRecord, *, exact_rule: str, message: str) -> None:
        print(f"[{_clock()}] UNBLOCK  Manual unblock completed")
        print(f"                     Source IP: {block.source_ip}")
        print(f"                     Block ID: {block.block_id}")
        print(f"                     Exact rule removed: {exact_rule}")
        print("                     Database updated: YES")
        print(f"                     Result: {message}")

    def print_expired_block(self, block: BlockRecord, *, firewall_message: str) -> None:
        print(f"[{_clock()}] UNBLOCK  Temporary block expired")
        print(f"                     Source IP: {block.source_ip}")
        print("                     Exact rule removed: YES")
        print("                     Database updated: YES")
        print(f"                     Firewall: {firewall_message}")

    def print_status(self, rows: list[tuple[str, Any]]) -> None:
        print_table(("Item", "Value"), [(name, str(value)) for name, value in rows])

    def print_detections(self, detections: list[Detection]) -> None:
        rows = [
            (
                _display_time(item.created_at),
                item.source_ip,
                item.failed_count,
                item.unique_usernames,
                item.network_connection_count,
                item.risk_score,
                item.classification.value,
                item.decision.value,
            )
            for item in detections
        ]
        print_table(
            (
                "Time",
                "Source IP",
                "Failed",
                "Users",
                "Net",
                "Score",
                "Class",
                "Decision",
            ),
            rows,
        )

    def print_blocks(self, blocks: list[BlockRecord], *, rules_by_ip: dict[str, str]) -> None:
        now = datetime.now(timezone.utc)
        rows = []
        for block in blocks:
            remaining = "-"
            if block.status.value == "Active":
                remaining_seconds = max(0, int((block.expires_at - now).total_seconds()))
                remaining = f"{remaining_seconds}s"
            rows.append(
                (
                    block.source_ip,
                    _display_time(block.blocked_at),
                    _display_time(block.expires_at),
                    remaining,
                    block.status.value,
                    block.removal_method or "-",
                    rules_by_ip.get(block.source_ip, "-"),
                )
            )
        print_table(
            ("Source IP", "Blocked", "Expires", "Remaining", "Status", "Removal", "Rule"),
            rows,
        )

    def print_rules(self, rules: list[str]) -> None:
        if not rules:
            print("No SSH_SECURITY_APP rules are currently present.")
            return
        for rule in rules:
            print(rule)

    def print_allowlist(self, rows: list[dict[str, Any]]) -> None:
        print_table(
            ("ID", "IP Address", "Description", "Expires"),
            [
                (
                    row.get("allowlist_id", ""),
                    row.get("ip_address", ""),
                    row.get("description", ""),
                    row.get("expires_at") or "-",
                )
                for row in rows
            ],
        )

    def _print_source_profile(
        self,
        *,
        source_profile: dict[str, Any] | None,
        recent_auth_events: list[AuthenticationEvent],
        recent_network_events: list[NetworkEvent],
    ) -> None:
        print("                     Source machine info: local observations only")
        if source_profile:
            print(f"                     IP category: {source_profile.get('ip_category', '-')}")
            first_seen = _display_stored_time(source_profile.get("first_seen"))
            last_seen = _display_stored_time(source_profile.get("last_seen"))
            print(f"                     First seen: {first_seen}")
            print(f"                     Last seen: {last_seen}")
            print(
                "                     Total failed SSH logins: "
                f"{source_profile.get('failed_count_total', 0)}"
            )
            print(
                "                     Total successful SSH logins: "
                f"{source_profile.get('successful_count_total', 0)}"
            )
            print(
                "                     Detections recorded: "
                f"{source_profile.get('detection_count', 0)}"
            )
            print(f"                     Blocks recorded: {source_profile.get('block_count', 0)}")
            print(
                "                     Current block status: "
                f"{source_profile.get('current_block_status') or '-'}"
            )
        usernames = sorted({event.username for event in recent_auth_events if event.username})
        if usernames:
            print(f"                     Usernames attempted: {_compact_list(usernames)}")
        source_ports = sorted({event.source_port for event in recent_network_events})
        if source_ports:
            print(f"                     TCP source ports seen: {_compact_list(source_ports)}")
        tcp_flags = sorted({event.tcp_flags for event in recent_network_events})
        if tcp_flags:
            print(f"                     TCP flags seen: {_compact_list(tcp_flags)}")


def print_table(headers: tuple[str, ...], rows: list[tuple[Any, ...]]) -> None:
    values = [tuple(str(value) for value in row) for row in rows]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in values))
        if values
        else len(headers[index])
        for index in range(len(headers))
    ]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in values:
        print("  ".join(row[index].ljust(widths[index]) for index in range(len(headers))))


def _clock() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _display_time(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def _display_stored_time(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "-"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    return _display_time(parsed)


def _compact_list(values: list[Any], *, limit: int = 8) -> str:
    rendered = [str(value) for value in values]
    if len(rendered) <= limit:
        return ", ".join(rendered)
    shown = ", ".join(rendered[:limit])
    return f"{shown}, ... (+{len(rendered) - limit} more)"
