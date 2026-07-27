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
from threading import Event

from ssh_security_app.audit import AuditService, configure_logging
from ssh_security_app.collectors.auth_ingestor import AuthenticationIngestor
from ssh_security_app.collectors.auth_journal import AuthenticationJournalCollector, CollectorError
from ssh_security_app.collectors.network_ingestor import NetworkIngestor
from ssh_security_app.collectors.network_tcpdump import NetworkTcpdumpCollector
from ssh_security_app.config import ConfigurationError, Settings, load_config
from ssh_security_app.constants import BlockStatus, Decision, HealthState, OperatingMode
from ssh_security_app.core.allowlist import AllowlistManager
from ssh_security_app.core.correlation import DetectionEngine
from ssh_security_app.core.modes import OperatingModeManager
from ssh_security_app.db.database import Database, DatabaseError
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.health import HealthMonitor
from ssh_security_app.models import HealthStatus
from ssh_security_app.response.action_request_worker import ActionRequestWorker
from ssh_security_app.response.block_manager import BlockManager
from ssh_security_app.response.expiration_worker import ExpirationWorker
from ssh_security_app.response.firewall_manager import FirewallManager
from ssh_security_app.response.reconciliation import FirewallReconciler
from ssh_security_app.response.response_worker import ResponseWorker
from ssh_security_app.service import ApplicationController
from ssh_security_app.ui.action_requests import ManualUnblockRequestService
from ssh_security_app.ui.dashboard_data import DashboardDataService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-security-app",
        description="SSH Security Application evidence collection and risk analysis",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="optional JSON file merged over config/default.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate-config", help="validate configuration and exit")
    subparsers.add_parser("init-db", help="initialize or verify the SQLite schema")
    subparsers.add_parser("mode-status", help="show the configured and active operating mode")
    inspect = subparsers.add_parser(
        "inspect",
        help="inspect stored results as JSON without writing raw SQLite queries",
    )
    inspect.add_argument(
        "view",
        choices=(
            "overview",
            "detections",
            "active-blocks",
            "allowlist",
            "actions",
            "audit",
            "health",
        ),
    )
    inspect.add_argument("--limit", type=_positive_int, default=100)
    subparsers.add_parser(
        "service",
        help="run collectors, correlation, and response as one managed service",
    )

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
    detect.add_argument(
        "--apply-response",
        action="store_true",
        help="allow guarded firewall response; requires automatic_response mode",
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

    subparsers.add_parser(
        "firewall-status",
        help="inspect the dedicated project chain without changing it",
    )
    firewall_init = subparsers.add_parser(
        "firewall-init",
        help="create only the dedicated chain and its TCP/SSH INPUT jump",
    )
    firewall_init.add_argument(
        "--confirm-firewall-changes",
        action="store_true",
        help="required acknowledgement for firewall mutation",
    )
    firewall_cleanup = subparsers.add_parser(
        "firewall-cleanup",
        help="safely remove recognized project rules, jump, and chain",
    )
    firewall_cleanup.add_argument(
        "--confirm-firewall-changes",
        action="store_true",
        help="required acknowledgement for firewall mutation",
    )
    subparsers.add_parser(
        "response-reconcile",
        help="reconcile active database blocks with the project chain once",
    )
    subparsers.add_parser(
        "response-worker",
        help="run expiration, manual-unblock, and reconciliation processing",
    )
    unblock = subparsers.add_parser(
        "manual-unblock-request",
        help="queue an unprivileged SQLite manual-unblock request",
    )
    unblock.add_argument("block_id")
    unblock.add_argument("source_ip")
    unblock.add_argument("--reason", required=True)
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
        logging.getLogger("ssh_security_app.main").exception("database initialization failed")
        print(f"Database error: {exc}", file=sys.stderr)
        return 1

    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    health = HealthMonitor(repositories.health)
    mode_manager = OperatingModeManager(repositories.application_state, audit)
    active_mode = mode_manager.activate(settings.response.mode)

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
    if args.command == "mode-status":
        print(f"Configured mode={settings.response.mode.value}; active mode={active_mode.value}")
        return 0
    if args.command == "inspect":
        return _run_inspection(args, repositories, active_mode)
    if args.command == "service":
        return _run_application_service(settings, database, repositories, audit, health)

    if args.command == "collect-auth":
        return _run_authentication_collection(args, settings, repositories, audit, health)
    if args.command == "collect-network":
        return _run_network_collection(args, settings, repositories, audit, health)
    if args.command == "detect":
        return _run_detection(args, settings, database, repositories, audit, health)
    if args.command.startswith("allowlist-"):
        return _run_allowlist(args, repositories, audit)
    if args.command.startswith("firewall-"):
        return _run_firewall(args, settings, repositories, audit, health)
    if args.command == "manual-unblock-request":
        return _queue_manual_unblock(args, repositories, audit)
    if args.command in {"response-reconcile", "response-worker"}:
        return _run_response(args, settings, repositories, audit, health)
    raise RuntimeError(f"unhandled command: {args.command}")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1 or parsed > 1000:
        raise argparse.ArgumentTypeError("limit must be between 1 and 1000")
    return parsed


def _run_inspection(
    args: argparse.Namespace,
    repositories: RepositorySet,
    active_mode: OperatingMode,
) -> int:
    data = DashboardDataService(repositories)
    views = {
        "overview": lambda: data.overview_dict(active_mode),
        "detections": lambda: data.detection_rows(args.limit),
        "active-blocks": lambda: data.active_block_rows(limit=args.limit),
        "allowlist": lambda: data.allowlist_rows(args.limit),
        "actions": lambda: data.action_request_rows(args.limit),
        "audit": lambda: data.audit_rows(args.limit),
        "health": data.health_rows,
    }
    print(json.dumps(views[args.view](), indent=2, default=str))
    return 0


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
        logging.getLogger("ssh_security_app.main").exception("authentication collection failed")
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
        logging.getLogger("ssh_security_app.main").exception("network collection failed")
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
    health: HealthMonitor,
) -> int:
    try:
        if args.apply_response and settings.response.mode is not OperatingMode.AUTOMATIC_RESPONSE:
            raise ValueError("--apply-response requires response.mode=automatic_response")
        window_end = _parse_datetime(args.window_end) if args.window_end else None
        firewall_manager = None
        block_manager = None
        if args.apply_response:
            firewall_manager = _build_firewall_manager(settings, health, audit)
            block_manager = BlockManager(
                firewall=firewall_manager,
                blocks=repositories.blocks,
                allowlist=repositories.allowlist,
                audit=audit,
                duration_seconds=settings.response.block_duration_seconds,
                protected_addresses=settings.network_sensor.protected_ipv4_addresses,
            )
        engine = DetectionEngine(
            database=database,
            repositories=repositories,
            settings=settings,
            audit=audit,
            firewall_manager=firewall_manager,
            block_manager=block_manager,
        )
        if args.source_ip:
            detection = engine.run_for_source(args.source_ip, window_end=window_end)
            detections = [detection] if detection else []
        else:
            detections = engine.run_all(window_end=window_end)
    except (ValueError, DatabaseError) as exc:
        health.failed("correlation_engine", str(exc))
        print(f"Detection error: {exc}", file=sys.stderr)
        return 2

    health.healthy("correlation_engine", detections_created=len(detections))
    if not detections:
        print("No new detection met the threshold, or the evidence was already analyzed.")
        return 0
    command_failed = False
    for detection in detections:
        print(
            f"Detection {detection.detection_id}: source={detection.source_ip}, "
            f"score={detection.risk_score}, classification={detection.classification.value}, "
            f"decision={detection.decision.value}"
        )
        print(f"Reason: {detection.decision_reason}")
        print(f"Breakdown: {json.dumps(detection.risk_breakdown, sort_keys=True)}")
        if detection.decision is Decision.WOULD_BLOCK:
            minutes = settings.response.block_duration_seconds // 60
            print(
                f"Simulation: would block {detection.source_ip} for {minutes} minutes; "
                "no firewall change was made."
            )
        block_response = engine.block_responses.get(detection.detection_id)
        if block_response is not None:
            print(f"Firewall response: {block_response.message}")
            command_failed = command_failed or not block_response.success
    return 1 if command_failed else 0


def _run_firewall(
    args: argparse.Namespace,
    settings: Settings,
    repositories: RepositorySet,
    audit: AuditService,
    health: HealthMonitor,
) -> int:
    if args.command in {"firewall-init", "firewall-cleanup"}:
        if settings.response.mode is not OperatingMode.AUTOMATIC_RESPONSE:
            print(
                "Firewall changes require response.mode=automatic_response.",
                file=sys.stderr,
            )
            return 2
        if not args.confirm_firewall_changes:
            print(
                "Refusing firewall changes without --confirm-firewall-changes.",
                file=sys.stderr,
            )
            return 2

    manager = _build_firewall_manager(settings, health, audit)
    if args.command == "firewall-status":
        healthy, firewall_ready = manager.inspect_readiness()
        print(
            f"Firewall executable healthy={healthy}; "
            f"project chain and INPUT jump ready={firewall_ready}"
        )
        if not healthy or not firewall_ready:
            return 1
        list_result, rules = manager.list_project_rules()
        if not list_result.success:
            print(f"Firewall status error: {list_result.message}", file=sys.stderr)
            return 1
        print("\n".join(rules) if rules else "Project chain contains no rules.")
        return 0

    cleanup = args.command == "firewall-cleanup"
    result = manager.cleanup_project_chain() if cleanup else manager.initialize_chain()
    action = "firewall_cleanup" if cleanup else "firewall_initialization"
    audit.record(
        component="firewall_manager",
        action=action,
        target=settings.response.iptables_chain,
        result="success" if result.success else "failure",
        details={"changed": result.changed, "message": result.message},
    )
    if cleanup and result.success and result.changed:
        for block in repositories.blocks.list_active(limit=10_000):
            repositories.blocks.mark_removed(
                block.block_id,
                status=BlockStatus.INCONSISTENT,
                removal_method="Explicit cleanup",
                error_message="project firewall chain was explicitly removed",
            )
    print(result.message)
    return 0 if result.success else 1


def _queue_manual_unblock(
    args: argparse.Namespace,
    repositories: RepositorySet,
    audit: AuditService,
) -> int:
    service = ManualUnblockRequestService(
        requests=repositories.action_requests,
        blocks=repositories.blocks,
        audit=audit,
    )
    try:
        request = service.request(
            block_id=args.block_id,
            source_ip=args.source_ip,
            reason=args.reason,
        )
    except ValueError as exc:
        print(f"Manual unblock request error: {exc}", file=sys.stderr)
        return 2
    print(f"Manual unblock request queued: {request.request_id}")
    return 0


def _run_response(
    args: argparse.Namespace,
    settings: Settings,
    repositories: RepositorySet,
    audit: AuditService,
    health: HealthMonitor,
) -> int:
    if settings.response.mode is not OperatingMode.AUTOMATIC_RESPONSE:
        print(
            "Response processing requires response.mode=automatic_response.",
            file=sys.stderr,
        )
        return 2
    firewall = _build_firewall_manager(settings, health, audit)
    executable_healthy, ready = firewall.inspect_readiness()
    if not executable_healthy or not ready:
        print(
            "Project firewall chain is not ready. Run firewall-init first.",
            file=sys.stderr,
        )
        return 1
    reconciler = FirewallReconciler(
        firewall=firewall,
        blocks=repositories.blocks,
        audit=audit,
        health=health,
    )
    if args.command == "response-reconcile":
        result = reconciler.reconcile()
        print(json.dumps(result.__dict__, indent=2, sort_keys=True))
        return 1 if result.failed else 0

    expiration = ExpirationWorker(
        firewall=firewall,
        blocks=repositories.blocks,
        audit=audit,
        health=health,
    )
    actions = ActionRequestWorker(
        firewall=firewall,
        requests=repositories.action_requests,
        blocks=repositories.blocks,
        audit=audit,
        health=health,
    )
    worker = ResponseWorker(
        expiration=expiration,
        actions=actions,
        reconciler=reconciler,
        health=health,
        interval_seconds=settings.response.expiration_check_seconds,
    )
    stop_event = Event()
    previous_handlers: dict[signal.Signals, object] = {}

    def stop_handler(_signum: int, _frame: object) -> None:
        stop_event.set()

    try:
        for monitored_signal in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[monitored_signal] = signal.getsignal(monitored_signal)
            signal.signal(monitored_signal, stop_handler)
        worker.run(stop_event)
    finally:
        for monitored_signal, previous in previous_handlers.items():
            signal.signal(monitored_signal, previous)
    return 0


def _run_application_service(
    settings: Settings,
    database: Database,
    repositories: RepositorySet,
    audit: AuditService,
    health: HealthMonitor,
) -> int:
    auth_ingestor = AuthenticationIngestor(
        auth_events=repositories.auth_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        protected_addresses=settings.network_sensor.protected_ipv4_addresses,
    )
    authentication_collector = AuthenticationJournalCollector(
        settings.authentication_sensor,
        on_line=auth_ingestor.process_line,
        on_health=_health_callback(health, audit),
    )
    network_ingestor = NetworkIngestor(
        network_events=repositories.network_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        interface_name=settings.network_sensor.interface,
        ssh_port=settings.network_sensor.ssh_port,
    )
    network_collector = NetworkTcpdumpCollector(
        settings.network_sensor,
        on_line=network_ingestor.process_line,
        on_health=_health_callback(health, audit),
    )

    firewall = None
    block_manager = None
    response_worker = None
    if settings.response.mode is OperatingMode.AUTOMATIC_RESPONSE:
        firewall = _build_firewall_manager(settings, health, audit)
        executable_healthy, ready = firewall.inspect_readiness()
        if not executable_healthy or not ready:
            print(
                "Automatic-response service requires an initialized project firewall chain.",
                file=sys.stderr,
            )
            return 1
        block_manager = BlockManager(
            firewall=firewall,
            blocks=repositories.blocks,
            allowlist=repositories.allowlist,
            audit=audit,
            duration_seconds=settings.response.block_duration_seconds,
            protected_addresses=settings.network_sensor.protected_ipv4_addresses,
        )
        reconciler = FirewallReconciler(
            firewall=firewall,
            blocks=repositories.blocks,
            audit=audit,
            health=health,
        )
        response_worker = ResponseWorker(
            expiration=ExpirationWorker(
                firewall=firewall,
                blocks=repositories.blocks,
                audit=audit,
                health=health,
            ),
            actions=ActionRequestWorker(
                firewall=firewall,
                requests=repositories.action_requests,
                blocks=repositories.blocks,
                audit=audit,
                health=health,
            ),
            reconciler=reconciler,
            health=health,
            interval_seconds=settings.response.expiration_check_seconds,
        )

    detector = DetectionEngine(
        database=database,
        repositories=repositories,
        settings=settings,
        audit=audit,
        firewall_manager=firewall,
        block_manager=block_manager,
    )
    controller = ApplicationController(
        authentication_collector=authentication_collector,
        network_collector=network_collector,
        detector=detector,
        response_worker=response_worker,
        audit=audit,
        health=health,
    )
    stop_event = Event()
    previous_handlers: dict[signal.Signals, object] = {}

    def stop_handler(_signum: int, _frame: object) -> None:
        stop_event.set()

    try:
        for monitored_signal in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[monitored_signal] = signal.getsignal(monitored_signal)
            signal.signal(monitored_signal, stop_handler)
        controller.run(stop_event)
    finally:
        for monitored_signal, previous in previous_handlers.items():
            signal.signal(monitored_signal, previous)
    return 0


def _build_firewall_manager(
    settings: Settings,
    health: HealthMonitor,
    audit: AuditService,
) -> FirewallManager:
    return FirewallManager(
        settings.response,
        ssh_port=settings.network_sensor.ssh_port,
        on_health=_health_callback(health, audit),
    )


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
