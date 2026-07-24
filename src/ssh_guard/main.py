"""Command-line controller for the currently implemented project stages."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from ssh_guard.audit import AuditService, configure_logging
from ssh_guard.collectors.auth_ingestor import AuthenticationIngestor
from ssh_guard.collectors.auth_journal import AuthenticationJournalCollector, CollectorError
from ssh_guard.collectors.network_ingestor import NetworkIngestor
from ssh_guard.collectors.network_tcpdump import NetworkTcpdumpCollector
from ssh_guard.config import ConfigurationError, Settings, load_config
from ssh_guard.constants import HealthState
from ssh_guard.core.allowlist import AllowlistManager
from ssh_guard.core.correlation import DetectionEngine
from ssh_guard.db.database import Database, DatabaseError
from ssh_guard.db.repositories import RepositorySet
from ssh_guard.health import HealthMonitor
from ssh_guard.models import HealthStatus


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-guard",
        description="SSH Brute Guard evidence collection and risk analysis",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="optional JSON file merged over config/default.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate-config", help="validate configuration and exit")
    subparsers.add_parser("init-db", help="initialize or verify the SQLite schema")

    collect = subparsers.add_parser(
        "collect-auth",
        help="collect OpenSSH authentication evidence",
    )
    mode = collect.add_mutually_exclusive_group()
    mode.add_argument("--fixture", type=Path, help="read sanitized fixture records")
    mode.add_argument("--follow", action="store_true", help="follow new journal records")
    mode.add_argument("--once", action="store_true", help="read recent journal records and exit")
    collect.add_argument(
        "--since",
        help="journalctl --since value, for example '2026-07-24 08:00:00'",
    )

    network = subparsers.add_parser(
        "collect-network",
        help="collect filtered TCP destination-port 22 metadata",
    )
    network_mode = network.add_mutually_exclusive_group()
    network_mode.add_argument("--fixture", type=Path, help="read sanitized tcpdump records")
    network_mode.add_argument("--follow", action="store_true", help="run live tcpdump collection")

    detect = subparsers.add_parser(
        "detect",
        help="correlate stored evidence and create explainable detections",
    )
    detection_target = detect.add_mutually_exclusive_group(required=True)
    detection_target.add_argument("--source-ip", help="analyze one source IP")
    detection_target.add_argument("--all", action="store_true", help="analyze all candidate IPs")
    detect.add_argument(
        "--window-end",
        help="UTC-aware ISO timestamp; defaults to the current time",
    )

    allowlist_add = subparsers.add_parser("allowlist-add", help="add a validated IPv4 entry")
    allowlist_add.add_argument("ip_address")
    allowlist_add.add_argument("--description", required=True)
    allowlist_add.add_argument("--reason", required=True)
    allowlist_add.add_argument("--created-by", required=True)
    allowlist_add.add_argument("--expires-at", help="optional UTC-aware ISO timestamp")
    allowlist_add.add_argument("--notes")

    subparsers.add_parser("allowlist-list", help="list active allowlist entries")
    allowlist_disable = subparsers.add_parser(
        "allowlist-disable",
        help="disable an allowlist entry by ID",
    )
    allowlist_disable.add_argument("allowlist_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = load_config(args.config)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate-config":
        print(
            f"Configuration is valid. Mode={settings.response.mode.value}; "
            f"environment={settings.application.environment}"
        )
        return 0

    configure_logging(settings.logging)
    database = Database(
        settings.database.path,
        busy_timeout_seconds=settings.database.busy_timeout_seconds,
        wal_mode=settings.database.wal_mode,
    )
    try:
        database.initialize()
    except DatabaseError as exc:
        logging.getLogger("ssh_guard.main").exception("database initialization failed")
        print(f"Database error: {exc}", file=sys.stderr)
        return 1

    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    health = HealthMonitor(repositories.health)

    if args.command == "init-db":
        health.healthy("database", path=settings.database.path)
        audit.record(
            component="database",
            action="database_initialized",
            target=settings.database.path,
            result="success",
        )
        print(f"Database initialized: {settings.database.path}")
        return 0

    if args.command == "collect-auth":
        return _run_authentication_collection(args, settings, repositories, audit, health)
    if args.command == "collect-network":
        return _run_network_collection(args, settings, repositories, audit, health)
    if args.command == "detect":
        return _run_detection(args, settings, database, repositories, audit)
    if args.command.startswith("allowlist-"):
        return _run_allowlist(args, repositories, audit)
    raise RuntimeError(f"unhandled command: {args.command}")


def _run_authentication_collection(
    args: argparse.Namespace,
    settings: Settings,
    repositories: RepositorySet,
    audit: AuditService,
    health: HealthMonitor,
) -> int:
    ingestor = AuthenticationIngestor(
        auth_events=repositories.auth_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        protected_addresses=settings.network_sensor.protected_ipv4_addresses,
    )

    def record_health(status: HealthStatus) -> None:
        health.record(status)
        if status.status is HealthState.FAILED:
            audit.record(
                component=status.component,
                action="sensor_failure",
                result="failure",
                details={"error": status.last_error, **status.details},
            )

    collector = AuthenticationJournalCollector(
        settings.authentication_sensor,
        on_line=ingestor.process_line,
        on_health=record_health,
    )
    audit.record(
        component="application",
        action="application_startup",
        result="success",
        details={
            "mode": settings.response.mode.value,
            "collector": "authentication",
        },
    )

    previous_handlers: dict[signal.Signals, object] = {}

    def stop_handler(_signum: int, _frame: object) -> None:
        collector.stop()

    try:
        if args.follow:
            for monitored_signal in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[monitored_signal] = signal.getsignal(monitored_signal)
                signal.signal(monitored_signal, stop_handler)
            count = collector.follow(since=args.since)
        elif args.fixture:
            count = collector.collect_fixture(args.fixture)
        else:
            count = collector.collect_once(since=args.since)
    except (CollectorError, DatabaseError, OSError) as exc:
        audit.record(
            component="authentication_sensor",
            action="collection_failed",
            result="failure",
            details={"error": str(exc)},
        )
        logging.getLogger("ssh_guard.main").exception("authentication collection failed")
        return 1
    finally:
        for monitored_signal, previous in previous_handlers.items():
            signal.signal(monitored_signal, previous)
        audit.record(
            component="application",
            action="application_shutdown",
            result="success",
        )

    print(
        "Authentication collection complete: "
        f"lines={count}, stored_events={repositories.auth_events.count()}, "
        f"parser_errors={repositories.parser_errors.count()}"
    )
    return 0


def _run_network_collection(
    args: argparse.Namespace,
    settings: Settings,
    repositories: RepositorySet,
    audit: AuditService,
    health: HealthMonitor,
) -> int:
    ingestor = NetworkIngestor(
        network_events=repositories.network_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        interface_name=settings.network_sensor.interface,
        ssh_port=settings.network_sensor.ssh_port,
    )
    collector = NetworkTcpdumpCollector(
        settings.network_sensor,
        on_line=ingestor.process_line,
        on_health=_health_callback(health, audit),
    )
    audit.record(
        component="application",
        action="application_startup",
        result="success",
        details={"mode": settings.response.mode.value, "collector": "network"},
    )
    previous_handlers: dict[signal.Signals, object] = {}

    def stop_handler(_signum: int, _frame: object) -> None:
        collector.stop()

    try:
        if args.fixture:
            count = collector.collect_fixture(args.fixture)
        else:
            for monitored_signal in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[monitored_signal] = signal.getsignal(monitored_signal)
                signal.signal(monitored_signal, stop_handler)
            count = collector.follow()
    except (CollectorError, DatabaseError, OSError) as exc:
        audit.record(
            component="network_sensor",
            action="collection_failed",
            result="failure",
            details={"error": str(exc)},
        )
        logging.getLogger("ssh_guard.main").exception("network collection failed")
        return 1
    finally:
        for monitored_signal, previous in previous_handlers.items():
            signal.signal(monitored_signal, previous)
        audit.record(component="application", action="application_shutdown", result="success")

    print(
        "Network collection complete: "
        f"lines={count}, stored_events={repositories.network_events.count()}, "
        f"parser_errors={repositories.parser_errors.count()}"
    )
    return 0


def _run_detection(
    args: argparse.Namespace,
    settings: Settings,
    database: Database,
    repositories: RepositorySet,
    audit: AuditService,
) -> int:
    try:
        window_end = _parse_datetime(args.window_end) if args.window_end else None
        engine = DetectionEngine(
            database=database,
            repositories=repositories,
            settings=settings,
            audit=audit,
        )
        if args.source_ip:
            detection = engine.run_for_source(args.source_ip, window_end=window_end)
            detections = [detection] if detection else []
        else:
            detections = engine.run_all(window_end=window_end)
    except (ValueError, DatabaseError) as exc:
        print(f"Detection error: {exc}", file=sys.stderr)
        return 2

    if not detections:
        print("No new detection met the threshold, or the evidence was already analyzed.")
        return 0
    for detection in detections:
        print(
            f"Detection {detection.detection_id}: source={detection.source_ip}, "
            f"score={detection.risk_score}, classification={detection.classification.value}, "
            f"decision={detection.decision.value}"
        )
        print(f"Reason: {detection.decision_reason}")
        print(f"Breakdown: {json.dumps(detection.risk_breakdown, sort_keys=True)}")
    return 0


def _run_allowlist(
    args: argparse.Namespace,
    repositories: RepositorySet,
    audit: AuditService,
) -> int:
    manager = AllowlistManager(repositories.allowlist, audit)
    try:
        if args.command == "allowlist-add":
            entry_id = manager.add_allowlist_entry(
                ip_address=args.ip_address,
                description=args.description,
                reason=args.reason,
                created_by=args.created_by,
                expires_at=_parse_datetime(args.expires_at) if args.expires_at else None,
                notes=args.notes,
            )
            print(f"Allowlist entry added: {entry_id}")
        elif args.command == "allowlist-disable":
            if not manager.disable_allowlist_entry(args.allowlist_id):
                print("Allowlist entry was not found or was already inactive.", file=sys.stderr)
                return 1
            print(f"Allowlist entry disabled: {args.allowlist_id}")
        else:
            entries = manager.list_active_entries()
            print(json.dumps(entries, indent=2, sort_keys=True, default=str))
    except ValueError as exc:
        print(f"Allowlist error: {exc}", file=sys.stderr)
        return 2
    return 0


def _health_callback(health: HealthMonitor, audit: AuditService):
    def record_health(status: HealthStatus) -> None:
        health.record(status)
        if status.status is HealthState.FAILED:
            audit.record(
                component=status.component,
                action="sensor_failure",
                result="failure",
                details={"error": status.last_error, **status.details},
            )

    return record_health


def _parse_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


if __name__ == "__main__":
    raise SystemExit(main())
