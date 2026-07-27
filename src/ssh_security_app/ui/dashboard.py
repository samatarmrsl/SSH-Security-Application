"""First-party local web dashboard backed only by the Python standard library."""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import signal
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ssh_security_app.audit import AuditService, configure_logging
from ssh_security_app.config import Settings, load_config
from ssh_security_app.constants import OperatingMode
from ssh_security_app.core.allowlist import AllowlistManager
from ssh_security_app.core.modes import OperatingModeManager
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet
from ssh_security_app.health import HealthMonitor
from ssh_security_app.ui.action_requests import ManualUnblockRequestService
from ssh_security_app.ui.dashboard_data import DashboardDataService

STATIC_DIRECTORY = Path(__file__).with_name("static")
MAX_REQUEST_BYTES = 16_384


@dataclass(frozen=True)
class DashboardActions:
    """Unprivileged actions that write requests or records to SQLite."""

    manual_unblocks: ManualUnblockRequestService
    allowlist: AllowlistManager


class DashboardApplication:
    """Own the dashboard query layer, action boundary, and CSRF secret."""

    def __init__(
        self,
        data: DashboardDataService,
        mode: OperatingMode,
        actions: DashboardActions,
        *,
        csrf_token: str | None = None,
    ) -> None:
        self.data = data
        self.mode = mode
        self.actions = actions
        self.csrf_token = csrf_token or secrets.token_urlsafe(32)

    def snapshot(self) -> dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overview": self.data.overview_dict(self.mode),
            "detections": self.data.detection_rows(),
            "active_blocks": self.data.active_block_rows(),
            "block_history": self.data.block_history_rows(),
            "allowlist": self.data.allowlist_rows(),
            "audit": self.data.audit_rows(),
            "action_requests": self.data.action_request_rows(),
            "health": self.data.health_rows(),
        }

    def submit_action(self, path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        try:
            if path == "/api/actions/manual-unblock":
                request = self.actions.manual_unblocks.request(
                    block_id=_required_text(payload, "block_id"),
                    source_ip=_required_text(payload, "source_ip"),
                    reason=_required_text(payload, "reason"),
                )
                return HTTPStatus.ACCEPTED, {
                    "message": "Manual unblock request queued for the response worker.",
                    "request_id": request.request_id,
                }
            if path == "/api/actions/allowlist-add":
                expires_text = str(payload.get("expires_at", "")).strip()
                entry_id = self.actions.allowlist.add_allowlist_entry(
                    ip_address=_required_text(payload, "ip_address"),
                    description=_required_text(payload, "description"),
                    reason=_required_text(payload, "reason"),
                    created_by=_required_text(payload, "created_by"),
                    expires_at=_parse_timestamp(expires_text) if expires_text else None,
                    notes=str(payload.get("notes", "")).strip() or None,
                )
                return HTTPStatus.CREATED, {
                    "message": "Allowlist entry added.",
                    "allowlist_id": entry_id,
                }
            if path == "/api/actions/allowlist-disable":
                entry_id = _required_text(payload, "allowlist_id")
                if not self.actions.allowlist.disable_allowlist_entry(entry_id):
                    return HTTPStatus.CONFLICT, {
                        "error": "Entry was already disabled or no longer exists."
                    }
                return HTTPStatus.OK, {"message": "Allowlist entry disabled."}
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, {"error": str(exc)}
        return HTTPStatus.NOT_FOUND, {"error": "Unknown dashboard action."}


class DashboardHTTPServer(ThreadingHTTPServer):
    """Threaded local HTTP server carrying the application object."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], application: DashboardApplication) -> None:
        self.application = application
        super().__init__(address, DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Serve only the owned static interface and its same-origin JSON API."""

    server: DashboardHTTPServer

    def do_GET(self) -> None:  # noqa: N802
        request = urlsplit(self.path)
        path = request.path
        if path == "/api/session":
            self._send_json({"csrf_token": self.server.application.csrf_token})
            return
        if path == "/api/snapshot":
            self._send_json(self.server.application.snapshot())
            return
        if path == "/api/ip-details":
            values = parse_qs(request.query).get("source_ip", [])
            if len(values) != 1:
                self._send_json(
                    {"error": "One source_ip query parameter is required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            try:
                detail = self.server.application.data.ip_detail(values[0])
            except ValueError as exc:
                self._send_json(
                    {"error": str(exc)},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            if detail is None:
                self._send_json(
                    {"error": "No stored profile exists for this IP address."},
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            self._send_json(detail)
            return
        asset = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
            "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }.get(path)
        if asset is None:
            self._send_json({"error": "Not found."}, status=HTTPStatus.NOT_FOUND)
            return
        filename, content_type = asset
        try:
            body = (STATIC_DIRECTORY / filename).read_bytes()
        except OSError:
            logging.getLogger(__name__).exception("dashboard asset could not be read")
            self._send_json(
                {"error": "Dashboard asset is unavailable."},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )
            return
        self._send(body, content_type=content_type)

    def do_POST(self) -> None:  # noqa: N802
        if self.headers.get("X-CSRF-Token") != self.server.application.csrf_token:
            self._send_json({"error": "Invalid CSRF token."}, status=HTTPStatus.FORBIDDEN)
            return
        content_type = self.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            self._send_json(
                {"error": "Content-Type must be application/json."},
                status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            )
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            self._send_json(
                {"error": "Request body is too large."},
                status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return
        try:
            payload = json.loads(self.rfile.read(content_length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(
                {"error": "Request body is not valid JSON."},
                status=HTTPStatus.BAD_REQUEST,
            )
            return
        if not isinstance(payload, dict):
            self._send_json(
                {"error": "JSON body must be an object."},
                status=HTTPStatus.BAD_REQUEST,
            )
            return
        status, response = self.server.application.submit_action(
            urlsplit(self.path).path,
            payload,
        )
        self._send_json(response, status=status)

    def log_message(self, message_format: str, *args: object) -> None:
        logging.getLogger("ssh_security_app.dashboard.http").info(message_format, *args)

    def _send_json(
        self,
        value: dict[str, Any],
        *,
        status: int = HTTPStatus.OK,
    ) -> None:
        self._send(
            json.dumps(value, default=str, separators=(",", ":")).encode("utf-8"),
            status=status,
            content_type="application/json; charset=utf-8",
            no_store=True,
        )

    def _send(
        self,
        body: bytes,
        *,
        content_type: str,
        status: int = HTTPStatus.OK,
        no_store: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if no_store:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def build_application(settings: Settings) -> tuple[DashboardApplication, HealthMonitor]:
    database = Database(
        settings.database.path,
        busy_timeout_seconds=settings.database.busy_timeout_seconds,
        wal_mode=settings.database.wal_mode,
    )
    database.initialize()
    repositories = RepositorySet(database)
    audit = AuditService(repositories.audit)
    active_mode = OperatingModeManager(
        repositories.application_state,
        audit,
    ).activate(settings.response.mode)
    health = HealthMonitor(repositories.health)
    application = DashboardApplication(
        DashboardDataService(
            repositories,
            iptables_path=settings.response.iptables_path,
            iptables_chain=settings.response.iptables_chain,
            ssh_port=settings.network_sensor.ssh_port,
        ),
        active_mode,
        DashboardActions(
            manual_unblocks=ManualUnblockRequestService(
                requests=repositories.action_requests,
                blocks=repositories.blocks,
                audit=audit,
            ),
            allowlist=AllowlistManager(repositories.allowlist, audit),
        ),
    )
    return application, health


def _required_text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field.replace('_', ' ')} is required")
    return value.strip()


def _parse_timestamp(value: str) -> datetime:
    normalized = value.strip()
    normalized = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("allowlist expiration must be a valid ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("allowlist expiration must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def main(
    argv: Sequence[str] | None = None,
    *,
    server_factory: Callable[
        [tuple[str, int], DashboardApplication],
        DashboardHTTPServer,
    ] = DashboardHTTPServer,
) -> int:
    parser = argparse.ArgumentParser(description="Run the first-party SSH Security dashboard")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    settings = load_config(args.config)
    configure_logging(settings.logging)
    application, health = build_application(settings)
    server = server_factory((settings.dashboard.host, settings.dashboard.port), application)
    health.healthy(
        "dashboard",
        host=settings.dashboard.host,
        port=settings.dashboard.port,
        implementation="first_party_standard_library",
        direct_firewall_access=False,
        sqlite_actions=True,
    )
    print(
        f"SSH Security dashboard: http://{settings.dashboard.host}:{settings.dashboard.port}",
        flush=True,
    )
    shutdown_started = Event()
    previous_handlers: dict[signal.Signals, Any] = {}

    def stop_handler(_signum: int, _frame: object) -> None:
        if shutdown_started.is_set():
            return
        shutdown_started.set()
        Thread(
            target=server.shutdown,
            name="ssh-security-app-dashboard-shutdown",
            daemon=True,
        ).start()

    try:
        for monitored_signal in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[monitored_signal] = signal.getsignal(monitored_signal)
            signal.signal(monitored_signal, stop_handler)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for monitored_signal, previous in previous_handlers.items():
            signal.signal(monitored_signal, previous)
        server.server_close()
        health.stopped("dashboard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
