"""Command-line controller for the currently implemented project stages."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event

from ssh_security_application.audit import (
    AuditService,
    configure_logging,
)
from ssh_security_application.config import (
    ConfigurationError,
    Settings,
    load_config,
)
from ssh_security_application.constants import (
    AuthenticationEventType,
    BlockStatus,
    HealthState,
    OperatingMode,
)
from ssh_security_application.evidence_collection.auth import (
    AuthenticationIngestor,
    AuthenticationJournalCollector,
    CollectorError,
)
from ssh_security_application.evidence_collection.network import (
    NetworkIngestor,
    NetworkTcpdumpCollector,
)
from ssh_security_application.health import HealthMonitor
from ssh_security_application.ip_validation import validate_ip_address
from ssh_security_application.iptables_firewall_response.firewall import (
    BlockManager,
    ExpirationWorker,
    FirewallError,
    FirewallManager,
    FirewallReconciler,
    ResponseWorker,
)
from ssh_security_application.models import BlockResponse, Detection, HealthStatus
from ssh_security_application.modes import (
    OperatingModeManager,
)
from ssh_security_application.service import (
    ApplicationController,
)
from ssh_security_application.sqlite_data_storage.storage import (
    Database,
    DatabaseError,
    RepositorySet,
)
from ssh_security_application.ssh_brute_force_detection.detection import (
    AllowlistManager,
    DetectionEngine,
)
from ssh_security_application.terminal import (
    TerminalInterface,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-security-app",
        description="SSH Security Application evidence collection and risk analysis",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="optional lab configuration JSON file",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate-config", help="validate configuration and exit")
    subparsers.add_parser("init-db", help="initialize or verify the SQLite schema")
    subparsers.add_parser("status", help="show mode, collectors, SQLite, firewall, and counts")
    detections = subparsers.add_parser("detections", help="show recent detections")
    detections.add_argument("--limit", type=_positive_int, default=20)
    blocks = subparsers.add_parser("blocks", help="show active and recently removed blocks")
    blocks.add_argument("--limit", type=_positive_int, default=20)
    subparsers.add_parser("rules", help="show only application-owned iptables rules")
    unblock = subparsers.add_parser("unblock", help="remove an active temporary block by IP")
    unblock.add_argument("source_ip")
    allowlist = subparsers.add_parser("allowlist", help="manage trusted IPv4 sources")
    allowlist_commands = allowlist.add_subparsers(dest="allowlist_command", required=True)
    allowlist_add = allowlist_commands.add_parser("add", help="add a validated IPv4 entry")
    allowlist_add.add_argument("ip_address")
    allowlist_add.add_argument("--reason", required=True)
    allowlist_add.add_argument("--description", default="Trusted lab source")
    allowlist_add.add_argument("--created-by", default="terminal")
    allowlist_add.add_argument("--expires-at", help="optional UTC-aware ISO timestamp")
    allowlist_add.add_argument("--notes")
    allowlist_commands.add_parser("list", help="list active allowlist entries")
    allowlist_remove = allowlist_commands.add_parser("remove", help="disable an allowlist entry")
    allowlist_remove.add_argument("allowlist_id")
    subparsers.add_parser("monitor", help="run live terminal monitoring")

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
        logging.getLogger("ssh_security_application.main").exception(
            "database initialization failed"
        )
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
    if args.command == "status":
        return _run_status(settings, database, repositories, active_mode, health, audit)
    if args.command == "detections":
        return _run_detections_table(args, repositories)
    if args.command == "blocks":
        return _run_blocks_table(args, settings, repositories, audit, health)
    if args.command == "rules":
        return _run_rules(settings, audit, health)
    if args.command == "monitor":
        return _run_application_service(settings, database, repositories, audit, health)

    if args.command == "collect-auth":
        return _run_authentication_collection(args, settings, repositories, audit, health)
    if args.command == "collect-network":
        return _run_network_collection(args, settings, repositories, audit, health)
    if args.command == "detect":
        return _run_detection(args, settings, database, repositories, audit, health)
    if args.command == "allowlist":
        return _run_allowlist(args, repositories, audit)
    if args.command == "unblock":
        return _run_unblock(args, settings, repositories, audit, health)
    if args.command.startswith("firewall-"):
        return _run_firewall(args, settings, repositories, audit, health)
    if args.command == "response-reconcile":
        return _run_response(args, settings, repositories, audit, health)
    raise RuntimeError(f"unhandled command: {args.command}")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1 or parsed > 1000:
        raise argparse.ArgumentTypeError("limit must be between 1 and 1000")
    return parsed


def _run_status(
    settings: Settings,
    database: Database,
    repositories: RepositorySet,
    active_mode: OperatingMode,
    health: HealthMonitor,
    audit: AuditService,
) -> int:
    firewall = _build_firewall_manager(settings, health, audit)
    executable_healthy, firewall_ready = firewall.inspect_readiness()
    auth_health = repositories.health.get("authentication_sensor")
    network_health = repositories.health.get("network_sensor")
    terminal = TerminalInterface()
    terminal.print_status(
        [
            ("configured mode", settings.response.mode.value),
            ("active mode", active_mode.value),
            ("authentication collector", auth_health.status.value if auth_health else "UNKNOWN"),
            ("network collector", network_health.status.value if network_health else "UNKNOWN"),
            ("sqlite", "HEALTHY" if database.check_health() else "FAILED"),
            ("iptables executable", "HEALTHY" if executable_healthy else "FAILED"),
            ("firewall chain", "READY" if firewall_ready else "NOT READY"),
            ("recent detections", repositories.detections.count()),
            ("active blocks", repositories.blocks.count_by_status(BlockStatus.ACTIVE)),
        ]
    )
    return 0


def _run_detections_table(args: argparse.Namespace, repositories: RepositorySet) -> int:
    TerminalInterface().print_detections(repositories.detections.list_recent(args.limit))
    return 0


def _run_blocks_table(
    args: argparse.Namespace,
    settings: Settings,
    repositories: RepositorySet,
    audit: AuditService,
    health: HealthMonitor,
) -> int:
    firewall = _build_firewall_manager(settings, health, audit)
    blocks = repositories.blocks.list_recent(args.limit)
    rules_by_ip = {
        block.source_ip: firewall.builder.source_drop_rule(block.source_ip)
        for block in blocks
        if block.status is BlockStatus.ACTIVE
    }
    TerminalInterface().print_blocks(blocks, rules_by_ip=rules_by_ip)
    return 0


def _run_rules(settings: Settings, audit: AuditService, health: HealthMonitor) -> int:
    firewall = _build_firewall_manager(settings, health, audit)
    _executable_healthy, ready = firewall.inspect_readiness()
    result, project_rules = firewall.list_project_rules()
    rules = [firewall.builder.input_jump_rule()]
    rules.extend(project_rules)
    if not result.success and not ready:
        print(result.message, file=sys.stderr)
        return 1
    TerminalInterface().print_rules(rules)
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
        logging.getLogger("ssh_security_application.main").exception(
            "authentication collection failed"
        )
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
        logging.getLogger("ssh_security_application.main").exception("network collection failed")
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
    terminal = TerminalInterface()
    for detection in detections:
        block_response = engine.block_responses.get(detection.detection_id)
        exact_rule = None
        input_jump_rule = None
        if firewall_manager is not None:
            input_jump_rule = firewall_manager.builder.input_jump_rule()
            exact_rule = firewall_manager.builder.source_drop_rule(detection.source_ip)
        _print_rich_detection(
            terminal,
            detection,
            settings=settings,
            repositories=repositories,
            block_response=block_response,
            exact_rule=exact_rule,
            input_jump_rule=input_jump_rule,
        )
        if block_response is not None:
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


def _run_unblock(
    args: argparse.Namespace,
    settings: Settings,
    repositories: RepositorySet,
    audit: AuditService,
    health: HealthMonitor,
) -> int:
    validation = validate_ip_address(
        args.source_ip,
        protected_addresses=settings.network_sensor.protected_ipv4_addresses,
    )
    if (
        not validation.is_valid
        or validation.normalized_ip is None
        or not validation.eligible_for_detection
    ):
        print(
            f"Unblock error: {validation.exclusion_reason or 'invalid source IP'}",
            file=sys.stderr,
        )
        return 2

    block = repositories.blocks.get_active(validation.normalized_ip)
    if block is None:
        print(f"Unblock error: no active block for {validation.normalized_ip}", file=sys.stderr)
        return 1

    firewall = _build_firewall_manager(settings, health, audit)
    exact_rule = firewall.builder.source_drop_rule(validation.normalized_ip)
    try:
        if not firewall.rule_exists(validation.normalized_ip):
            print(
                f"Unblock error: exact owned rule is not present: {exact_rule}",
                file=sys.stderr,
            )
            return 1
    except FirewallError as exc:
        print(f"Unblock error: could not verify exact rule: {exc}", file=sys.stderr)
        return 1

    result = firewall.delete_block_rule(validation.normalized_ip)
    if not result.success:
        print(f"Unblock error: {result.message}", file=sys.stderr)
        return 1
    updated = repositories.blocks.mark_removed(
        block.block_id,
        status=BlockStatus.MANUALLY_REMOVED,
        removal_method="Manual CLI",
        firewall_result=result.message,
    )
    if not updated:
        print(
            "Unblock error: firewall rule was removed but database update failed", file=sys.stderr
        )
        return 1
    audit.record(
        component="manual_unblock",
        action="manual_unblock",
        target=validation.normalized_ip,
        result="success",
        details={"block_id": block.block_id, "firewall": result.message},
    )
    TerminalInterface().print_unblock(block, exact_rule=exact_rule, message=result.message)
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
    worker = ResponseWorker(
        expiration=expiration,
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
    terminal = TerminalInterface()
    auth_ingestor = AuthenticationIngestor(
        auth_events=repositories.auth_events,
        parser_errors=repositories.parser_errors,
        ip_profiles=repositories.ip_profiles,
        audit=audit,
        protected_addresses=settings.network_sensor.protected_ipv4_addresses,
    )

    def process_authentication_line(line: str):
        event = auth_ingestor.process_line(line)
        if event is not None:
            terminal.print_auth_event(
                event,
                failures_in_window=_failures_in_window(
                    repositories,
                    source_ip=event.source_ip,
                    window_end=event.event_time,
                    window_seconds=settings.detection.window_seconds,
                ),
            )
        return event

    authentication_collector = AuthenticationJournalCollector(
        settings.authentication_sensor,
        on_line=process_authentication_line,
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

    def process_network_line(line: str):
        event = network_ingestor.process_line(line)
        if event is not None:
            terminal.print_network_event(event)
        return event

    network_collector = NetworkTcpdumpCollector(
        settings.network_sensor,
        on_line=process_network_line,
        on_health=_health_callback(health, audit),
    )

    firewall = None
    block_manager = None
    response_worker = None
    firewall_ready = False
    if settings.response.mode is OperatingMode.AUTOMATIC_RESPONSE:
        firewall = _build_firewall_manager(settings, health, audit)
        executable_healthy, ready = firewall.inspect_readiness()
        if not executable_healthy or not ready:
            print(
                "Automatic-response service requires an initialized project firewall chain.",
                file=sys.stderr,
            )
            return 1
        firewall_ready = True
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
                on_unblock=lambda block, message: terminal.print_expired_block(
                    block,
                    firewall_message=message,
                ),
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
    terminal.print_monitor_startup(settings, firewall_ready=firewall_ready)
    detection_runner = _TerminalDetectionRunner(
        detector=detector,
        terminal=terminal,
        settings=settings,
        firewall=firewall,
        repositories=repositories,
    )
    controller = ApplicationController(
        authentication_collector=authentication_collector,
        network_collector=network_collector,
        detector=detection_runner,
        response_worker=response_worker,
        audit=audit,
        health=health,
        detection_interval_seconds=5,
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
    command = getattr(args, "allowlist_command", None) or args.command.replace("allowlist-", "")
    try:
        if command == "add":
            entry_id = manager.add_allowlist_entry(
                ip_address=args.ip_address,
                description=args.description,
                reason=args.reason,
                created_by=args.created_by,
                expires_at=_parse_datetime(args.expires_at) if args.expires_at else None,
                notes=args.notes,
            )
            print(f"Allowlist entry added: {entry_id}")
        elif command in {"remove", "disable"}:
            if not manager.disable_allowlist_entry(args.allowlist_id):
                print("Allowlist entry was not found or was already inactive.", file=sys.stderr)
                return 1
            print(f"Allowlist entry disabled: {args.allowlist_id}")
        else:
            entries = manager.list_active_entries()
            TerminalInterface().print_allowlist(entries)
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


class _TerminalDetectionRunner:
    def __init__(
        self,
        *,
        detector: DetectionEngine,
        terminal: TerminalInterface,
        settings: Settings,
        firewall: FirewallManager | None,
        repositories: RepositorySet,
    ) -> None:
        self.detector = detector
        self.terminal = terminal
        self.settings = settings
        self.firewall = firewall
        self.repositories = repositories

    def run_all(self) -> list[object]:
        detections = self.detector.run_all()
        for detection in detections:
            block_response = self.detector.block_responses.get(detection.detection_id)
            exact_rule = None
            input_jump_rule = None
            if block_response and block_response.block and self.firewall is not None:
                input_jump_rule = self.firewall.builder.input_jump_rule()
                exact_rule = self.firewall.builder.source_drop_rule(block_response.block.source_ip)
            elif self.firewall is not None:
                input_jump_rule = self.firewall.builder.input_jump_rule()
                exact_rule = self.firewall.builder.source_drop_rule(detection.source_ip)
            _print_rich_detection(
                self.terminal,
                detection,
                settings=self.settings,
                repositories=self.repositories,
                block_response=block_response,
                exact_rule=exact_rule,
                input_jump_rule=input_jump_rule,
            )
        return detections


def _print_rich_detection(
    terminal: TerminalInterface,
    detection: Detection,
    *,
    settings: Settings,
    repositories: RepositorySet,
    block_response: BlockResponse | None,
    exact_rule: str | None,
    input_jump_rule: str | None,
) -> None:
    terminal.print_detection(
        detection,
        block_response=block_response,
        block_duration_seconds=settings.response.block_duration_seconds,
        exact_rule=exact_rule,
        input_jump_rule=input_jump_rule,
        source_profile=repositories.ip_profiles.get(detection.source_ip),
        recent_auth_events=_recent_auth_events_for_detection(repositories, detection),
        recent_network_events=_recent_network_events_for_detection(repositories, detection),
    )


def _recent_auth_events_for_detection(
    repositories: RepositorySet,
    detection: Detection,
):
    events = repositories.auth_events.list_recent(
        source_ip=detection.source_ip,
        since=detection.window_start,
        limit=25,
    )
    return [
        event
        for event in events
        if detection.window_start <= event.event_time <= detection.window_end
    ]


def _recent_network_events_for_detection(
    repositories: RepositorySet,
    detection: Detection,
):
    events = repositories.network_events.list_recent(
        source_ip=detection.source_ip,
        limit=50,
    )
    return [
        event
        for event in events
        if detection.window_start <= event.event_time <= detection.window_end
    ]


def _failures_in_window(
    repositories: RepositorySet,
    *,
    source_ip: str,
    window_end: datetime,
    window_seconds: int,
) -> int:
    window_start = window_end - timedelta(seconds=window_seconds)
    failure_types = {
        AuthenticationEventType.FAILED_PASSWORD,
        AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
    }
    return sum(
        1
        for event in repositories.auth_events.list_window(
            source_ip=source_ip,
            window_start=window_start,
            window_end=window_end,
        )
        if event.event_type in failure_types
    )


if __name__ == "__main__":
    raise SystemExit(main())
