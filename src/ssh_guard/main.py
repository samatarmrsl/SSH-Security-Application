"""Command-line controller for the currently implemented project stages."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from collections.abc import Sequence
from pathlib import Path

from ssh_guard.audit import AuditService, configure_logging
from ssh_guard.collectors.auth_ingestor import AuthenticationIngestor
from ssh_guard.collectors.auth_journal import AuthenticationJournalCollector, CollectorError
from ssh_guard.config import ConfigurationError, Settings, load_config
from ssh_guard.constants import HealthState
from ssh_guard.db.database import Database, DatabaseError
from ssh_guard.db.repositories import RepositorySet
from ssh_guard.health import HealthMonitor
from ssh_guard.models import HealthStatus


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-guard",
        description="SSH Brute Guard foundation and authentication evidence collector",
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

    return _run_authentication_collection(args, settings, repositories, audit, health)


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


if __name__ == "__main__":
    raise SystemExit(main())
