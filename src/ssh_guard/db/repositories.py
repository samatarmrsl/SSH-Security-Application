"""Repository APIs for all SQLite persistence."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from ssh_guard.constants import (
    ActionRequestStatus,
    AuthenticationEventType,
    AuthenticationResult,
    BlockStatus,
    Decision,
    DetectionClassification,
    HealthState,
    IPAddressCategory,
    ParseStatus,
)
from ssh_guard.db.database import Database
from ssh_guard.models import (
    ActionRequest,
    AuditRecord,
    AuthenticationEvent,
    BlockRecord,
    Detection,
    HealthStatus,
    NetworkEvent,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("database timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def from_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("limit must be a positive integer")
    return value


def _json_dump(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _json_load(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    decoded = json.loads(value)
    return decoded if isinstance(decoded, dict) else {"value": decoded}


class AuthenticationEventRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def insert(self, event: AuthenticationEvent) -> bool:
        success = {
            AuthenticationResult.SUCCESS: 1,
            AuthenticationResult.FAILURE: 0,
            AuthenticationResult.NEUTRAL: None,
        }[event.authentication_result]
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO auth_events (
                    event_id, event_time, collected_at, source_ip, username,
                    event_type, success, process_id, raw_message, parse_status,
                    fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    event.event_id,
                    to_iso(event.event_time),
                    to_iso(event.collected_at),
                    event.source_ip,
                    event.username,
                    event.event_type.value,
                    success,
                    event.process_id,
                    event.raw_message,
                    event.parse_status.value,
                    event.deduplication_key,
                ),
            )
        return cursor.rowcount == 1

    def get(self, event_id: str) -> AuthenticationEvent | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM auth_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        return _auth_event_from_row(row) if row else None

    def list_recent(
        self,
        *,
        source_ip: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuthenticationEvent]:
        bounded_limit = _limit(limit)
        since_value = to_iso(since)
        with self.database.connection() as connection:
            if source_ip is not None and since_value is not None:
                rows = connection.execute(
                    """
                    SELECT * FROM auth_events
                    WHERE source_ip = ? AND event_time >= ?
                    ORDER BY event_time DESC LIMIT ?
                    """,
                    (source_ip, since_value, bounded_limit),
                ).fetchall()
            elif source_ip is not None:
                rows = connection.execute(
                    """
                    SELECT * FROM auth_events
                    WHERE source_ip = ?
                    ORDER BY event_time DESC LIMIT ?
                    """,
                    (source_ip, bounded_limit),
                ).fetchall()
            elif since_value is not None:
                rows = connection.execute(
                    """
                    SELECT * FROM auth_events
                    WHERE event_time >= ?
                    ORDER BY event_time DESC LIMIT ?
                    """,
                    (since_value, bounded_limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM auth_events ORDER BY event_time DESC LIMIT ?",
                    (bounded_limit,),
                ).fetchall()
        return [_auth_event_from_row(row) for row in rows]

    def count(self) -> int:
        with self.database.connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM auth_events").fetchone()
        return int(row["count"])

    def list_window(
        self,
        *,
        source_ip: str,
        window_start: datetime,
        window_end: datetime,
    ) -> list[AuthenticationEvent]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM auth_events
                WHERE source_ip = ? AND event_time >= ? AND event_time <= ?
                ORDER BY event_time, event_id
                """,
                (source_ip, to_iso(window_start), to_iso(window_end)),
            ).fetchall()
        return [_auth_event_from_row(row) for row in rows]

    def list_failure_sources(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> list[str]:
        failure_types = (
            AuthenticationEventType.FAILED_PASSWORD.value,
            AuthenticationEventType.FAILED_PASSWORD_INVALID_USER.value,
        )
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT source_ip FROM auth_events
                WHERE event_time >= ? AND event_time <= ?
                  AND event_type IN (?, ?)
                ORDER BY source_ip
                """,
                (
                    to_iso(window_start),
                    to_iso(window_end),
                    *failure_types,
                ),
            ).fetchall()
        return [row["source_ip"] for row in rows]


def _auth_event_from_row(row: sqlite3.Row) -> AuthenticationEvent:
    success = row["success"]
    result = (
        AuthenticationResult.NEUTRAL
        if success is None
        else AuthenticationResult.SUCCESS
        if success
        else AuthenticationResult.FAILURE
    )
    event_time = from_iso(row["event_time"])
    collected_at = from_iso(row["collected_at"])
    if event_time is None or collected_at is None:
        raise ValueError("stored authentication event has missing timestamps")
    return AuthenticationEvent(
        event_id=row["event_id"],
        event_time=event_time,
        collected_at=collected_at,
        source_ip=row["source_ip"],
        username=row["username"],
        event_type=AuthenticationEventType(row["event_type"]),
        authentication_result=result,
        process_id=row["process_id"],
        raw_message=row["raw_message"],
        parse_status=ParseStatus(row["parse_status"]),
        deduplication_key=row["fingerprint"],
    )


class NetworkEventRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def insert(self, event: NetworkEvent) -> bool:
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO network_events (
                    event_id, event_time, collected_at, source_ip, destination_ip,
                    source_port, destination_port, tcp_flags, interface_name,
                    sensor_name, parse_status, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    event.event_id,
                    to_iso(event.event_time),
                    to_iso(event.collected_at),
                    event.source_ip,
                    event.destination_ip,
                    event.source_port,
                    event.destination_port,
                    event.tcp_flags,
                    event.interface_name,
                    event.sensor_name,
                    event.parse_status.value,
                    event.deduplication_key,
                ),
            )
        return cursor.rowcount == 1

    def get(self, event_id: str) -> NetworkEvent | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM network_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        return _network_event_from_row(row) if row else None

    def list_window(
        self,
        *,
        source_ip: str,
        window_start: datetime,
        window_end: datetime,
        destination_port: int | None = None,
    ) -> list[NetworkEvent]:
        with self.database.connection() as connection:
            if destination_port is None:
                rows = connection.execute(
                    """
                    SELECT * FROM network_events
                    WHERE source_ip = ? AND event_time >= ? AND event_time <= ?
                    ORDER BY event_time, event_id
                    """,
                    (source_ip, to_iso(window_start), to_iso(window_end)),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM network_events
                    WHERE source_ip = ? AND event_time >= ? AND event_time <= ?
                      AND destination_port = ?
                    ORDER BY event_time, event_id
                    """,
                    (
                        source_ip,
                        to_iso(window_start),
                        to_iso(window_end),
                        destination_port,
                    ),
                ).fetchall()
        return [_network_event_from_row(row) for row in rows]

    def count(self) -> int:
        with self.database.connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM network_events").fetchone()
        return int(row["count"])


def _network_event_from_row(row: sqlite3.Row) -> NetworkEvent:
    event_time = from_iso(row["event_time"])
    collected_at = from_iso(row["collected_at"])
    if event_time is None or collected_at is None:
        raise ValueError("stored network event has missing timestamps")
    return NetworkEvent(
        event_id=row["event_id"],
        event_time=event_time,
        collected_at=collected_at,
        source_ip=row["source_ip"],
        destination_ip=row["destination_ip"],
        source_port=row["source_port"],
        destination_port=row["destination_port"],
        tcp_flags=row["tcp_flags"],
        interface_name=row["interface_name"],
        sensor_name=row["sensor_name"],
        parse_status=ParseStatus(row["parse_status"]),
        deduplication_key=row["fingerprint"],
    )


class IPProfileRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def observe_authentication(
        self,
        event: AuthenticationEvent,
        category: IPAddressCategory,
    ) -> None:
        failed = int(
            event.event_type
            in {
                AuthenticationEventType.FAILED_PASSWORD,
                AuthenticationEventType.FAILED_PASSWORD_INVALID_USER,
            }
        )
        succeeded = int(event.authentication_result is AuthenticationResult.SUCCESS)
        success_at = to_iso(event.event_time) if succeeded else None
        event_time = to_iso(event.event_time)
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO ip_profiles (
                    source_ip, ip_category, first_seen, last_seen,
                    failed_count_total, successful_count_total, last_success_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_ip) DO UPDATE SET
                    ip_category = excluded.ip_category,
                    last_seen = CASE
                        WHEN excluded.last_seen > ip_profiles.last_seen
                        THEN excluded.last_seen ELSE ip_profiles.last_seen
                    END,
                    failed_count_total =
                        ip_profiles.failed_count_total + excluded.failed_count_total,
                    successful_count_total =
                        ip_profiles.successful_count_total + excluded.successful_count_total,
                    last_success_at = CASE
                        WHEN excluded.last_success_at IS NOT NULL
                        THEN excluded.last_success_at ELSE ip_profiles.last_success_at
                    END
                """,
                (
                    event.source_ip,
                    category.value,
                    event_time,
                    event_time,
                    failed,
                    succeeded,
                    success_at,
                ),
            )

    def get(self, source_ip: str) -> dict[str, Any] | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM ip_profiles WHERE source_ip = ?",
                (source_ip,),
            ).fetchone()
        return dict(row) if row else None

    def observe_network(self, event: NetworkEvent, category: IPAddressCategory) -> None:
        event_time = to_iso(event.event_time)
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO ip_profiles (
                    source_ip, ip_category, first_seen, last_seen
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(source_ip) DO UPDATE SET
                    ip_category = excluded.ip_category,
                    last_seen = CASE
                        WHEN excluded.last_seen > ip_profiles.last_seen
                        THEN excluded.last_seen ELSE ip_profiles.last_seen
                    END
                """,
                (event.source_ip, category.value, event_time, event_time),
            )

    def increment_detection_count(self, source_ip: str) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE ip_profiles
                SET detection_count = detection_count + 1
                WHERE source_ip = ?
                """,
                (source_ip,),
            )

    def set_current_block_status(self, source_ip: str, status: str | None) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                "UPDATE ip_profiles SET current_block_status = ? WHERE source_ip = ?",
                (status, source_ip),
            )


class DetectionRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def insert(
        self,
        detection: Detection,
        *,
        auth_event_ids: tuple[str, ...] = (),
        network_event_ids: tuple[str, ...] = (),
    ) -> bool:
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO detections (
                    detection_id, source_ip, window_start, window_end,
                    failed_count, successful_count, invalid_user_count,
                    unique_username_count, network_event_count, attempt_rate,
                    recent_success, previous_detection_count, previous_block_count,
                    allowlisted, risk_score, risk_breakdown, classification,
                    decision, decision_reason, created_at, evidence_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    detection.detection_id,
                    detection.source_ip,
                    to_iso(detection.window_start),
                    to_iso(detection.window_end),
                    detection.failed_count,
                    detection.successful_count,
                    detection.invalid_user_count,
                    detection.unique_usernames,
                    detection.network_connection_count,
                    detection.attempt_rate,
                    int(detection.recent_success),
                    detection.previous_detection_count,
                    detection.previous_block_count,
                    int(detection.allowlisted),
                    detection.risk_score,
                    _json_dump(detection.risk_breakdown),
                    detection.classification.value,
                    detection.decision.value,
                    detection.decision_reason,
                    to_iso(detection.created_at),
                    detection.evidence_fingerprint,
                ),
            )
            if cursor.rowcount == 1:
                connection.executemany(
                    """
                    INSERT INTO detection_auth_events (detection_id, auth_event_id)
                    VALUES (?, ?)
                    """,
                    ((detection.detection_id, event_id) for event_id in auth_event_ids),
                )
                connection.executemany(
                    """
                    INSERT INTO detection_network_events (detection_id, network_event_id)
                    VALUES (?, ?)
                    """,
                    ((detection.detection_id, event_id) for event_id in network_event_ids),
                )
        return cursor.rowcount == 1

    def get(self, detection_id: str) -> Detection | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM detections WHERE detection_id = ?",
                (detection_id,),
            ).fetchone()
        return _detection_from_row(row) if row else None

    def list_recent(self, limit: int = 100) -> list[Detection]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM detections ORDER BY created_at DESC LIMIT ?",
                (_limit(limit),),
            ).fetchall()
        return [_detection_from_row(row) for row in rows]

    def count(self) -> int:
        with self.database.connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM detections").fetchone()
        return int(row["count"])


def _detection_from_row(row: sqlite3.Row) -> Detection:
    window_start = from_iso(row["window_start"])
    window_end = from_iso(row["window_end"])
    created_at = from_iso(row["created_at"])
    if window_start is None or window_end is None or created_at is None:
        raise ValueError("stored detection has missing timestamps")
    return Detection(
        detection_id=row["detection_id"],
        source_ip=row["source_ip"],
        window_start=window_start,
        window_end=window_end,
        failed_count=row["failed_count"],
        successful_count=row["successful_count"],
        invalid_user_count=row["invalid_user_count"],
        unique_usernames=row["unique_username_count"],
        network_connection_count=row["network_event_count"],
        attempt_rate=row["attempt_rate"],
        recent_success=bool(row["recent_success"]),
        previous_detection_count=row["previous_detection_count"],
        previous_block_count=row["previous_block_count"],
        allowlisted=bool(row["allowlisted"]),
        risk_score=row["risk_score"],
        classification=DetectionClassification(row["classification"]),
        decision=Decision(row["decision"]),
        decision_reason=row["decision_reason"],
        created_at=created_at,
        risk_breakdown=_json_load(row["risk_breakdown"]),
        evidence_fingerprint=row["evidence_fingerprint"],
    )


class AllowlistRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add(
        self,
        *,
        ip_address: str,
        description: str,
        reason: str,
        created_by: str,
        expires_at: datetime | None = None,
        notes: str | None = None,
        allowlist_id: str | None = None,
    ) -> str:
        entry_id = allowlist_id or str(uuid.uuid4())
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO allowlist (
                    allowlist_id, ip_address, description, reason, created_at,
                    expires_at, active, created_by, notes
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    entry_id,
                    ip_address,
                    description,
                    reason,
                    to_iso(utc_now()),
                    to_iso(expires_at),
                    created_by,
                    notes,
                ),
            )
        return entry_id

    def disable(self, allowlist_id: str) -> bool:
        with self.database.transaction() as connection:
            cursor = connection.execute(
                "UPDATE allowlist SET active = 0 WHERE allowlist_id = ? AND active = 1",
                (allowlist_id,),
            )
        return cursor.rowcount == 1

    def get(self, allowlist_id: str) -> dict[str, Any] | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM allowlist WHERE allowlist_id = ?",
                (allowlist_id,),
            ).fetchone()
        return dict(row) if row else None

    def is_allowlisted(self, ip_address: str, *, at: datetime | None = None) -> bool:
        check_time = to_iso(at or utc_now())
        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM allowlist
                WHERE ip_address = ? AND active = 1
                  AND (expires_at IS NULL OR expires_at > ?)
                LIMIT 1
                """,
                (ip_address, check_time),
            ).fetchone()
        return row is not None

    def list_active(self, *, at: datetime | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM allowlist
                WHERE active = 1 AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC LIMIT ?
                """,
                (to_iso(at or utc_now()), _limit(limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def expire_old(self, *, at: datetime | None = None) -> int:
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE allowlist SET active = 0
                WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?
                """,
                (to_iso(at or utc_now()),),
            )
        return cursor.rowcount


class BlockRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def insert(self, block: BlockRecord) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO blocks (
                    block_id, source_ip, detection_id, blocked_at, expires_at,
                    removed_at, status, removal_method, firewall_result, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block.block_id,
                    block.source_ip,
                    block.detection_id,
                    to_iso(block.blocked_at),
                    to_iso(block.expires_at),
                    to_iso(block.removed_at),
                    block.status.value,
                    block.removal_method,
                    block.firewall_result,
                    block.error_message,
                ),
            )

    def get_active(self, source_ip: str) -> BlockRecord | None:
        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM blocks
                WHERE source_ip = ? AND status = ?
                ORDER BY blocked_at DESC LIMIT 1
                """,
                (source_ip, BlockStatus.ACTIVE.value),
            ).fetchone()
        return _block_from_row(row) if row else None

    def list_active(self, limit: int = 100) -> list[BlockRecord]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM blocks WHERE status = ? ORDER BY expires_at LIMIT ?",
                (BlockStatus.ACTIVE.value, _limit(limit)),
            ).fetchall()
        return [_block_from_row(row) for row in rows]


def _block_from_row(row: sqlite3.Row) -> BlockRecord:
    blocked_at = from_iso(row["blocked_at"])
    expires_at = from_iso(row["expires_at"])
    if blocked_at is None or expires_at is None:
        raise ValueError("stored block has missing timestamps")
    return BlockRecord(
        block_id=row["block_id"],
        source_ip=row["source_ip"],
        detection_id=row["detection_id"],
        blocked_at=blocked_at,
        expires_at=expires_at,
        removed_at=from_iso(row["removed_at"]),
        status=BlockStatus(row["status"]),
        removal_method=row["removal_method"],
        firewall_result=row["firewall_result"],
        error_message=row["error_message"],
    )


class ActionRequestRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def insert(self, request: ActionRequest) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO action_requests (
                    request_id, action_type, source_ip, block_id, requested_at,
                    requested_reason, status, processed_at, result_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.request_id,
                    request.action_type,
                    request.source_ip,
                    request.block_id,
                    to_iso(request.requested_at),
                    request.requested_reason,
                    request.status.value,
                    to_iso(request.processed_at),
                    request.result_message,
                ),
            )

    def list_pending(self, limit: int = 100) -> list[ActionRequest]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM action_requests WHERE status = ?
                ORDER BY requested_at LIMIT ?
                """,
                (ActionRequestStatus.PENDING.value, _limit(limit)),
            ).fetchall()
        return [_action_request_from_row(row) for row in rows]

    def complete(
        self,
        request_id: str,
        *,
        status: ActionRequestStatus,
        result_message: str,
        processed_at: datetime | None = None,
    ) -> bool:
        if status is ActionRequestStatus.PENDING:
            raise ValueError("a completed request cannot remain Pending")
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE action_requests
                SET status = ?, processed_at = ?, result_message = ?
                WHERE request_id = ? AND status = ?
                """,
                (
                    status.value,
                    to_iso(processed_at or utc_now()),
                    result_message,
                    request_id,
                    ActionRequestStatus.PENDING.value,
                ),
            )
        return cursor.rowcount == 1


def _action_request_from_row(row: sqlite3.Row) -> ActionRequest:
    requested_at = from_iso(row["requested_at"])
    if requested_at is None:
        raise ValueError("stored action request has no requested_at timestamp")
    return ActionRequest(
        request_id=row["request_id"],
        action_type=row["action_type"],
        source_ip=row["source_ip"],
        block_id=row["block_id"],
        requested_at=requested_at,
        requested_reason=row["requested_reason"],
        status=ActionRequestStatus(row["status"]),
        processed_at=from_iso(row["processed_at"]),
        result_message=row["result_message"],
    )


class AuditRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def insert(self, record: AuditRecord) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO audit_log (
                    audit_id, event_time, component, action, target, result, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.audit_id,
                    to_iso(record.event_time),
                    record.component,
                    record.action,
                    record.target,
                    record.result,
                    _json_dump(record.details),
                ),
            )

    def list_recent(self, limit: int = 100) -> list[AuditRecord]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY event_time DESC LIMIT ?",
                (_limit(limit),),
            ).fetchall()
        records = []
        for row in rows:
            event_time = from_iso(row["event_time"])
            if event_time is None:
                raise ValueError("stored audit record has no timestamp")
            records.append(
                AuditRecord(
                    audit_id=row["audit_id"],
                    event_time=event_time,
                    component=row["component"],
                    action=row["action"],
                    target=row["target"],
                    result=row["result"],
                    details=_json_load(row["details"]),
                )
            )
        return records


class ParserErrorRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def record(
        self,
        *,
        sensor: str,
        raw_message: str,
        error_message: str,
        event_time: datetime | None = None,
        error_id: str | None = None,
    ) -> str:
        identifier = error_id or str(uuid.uuid4())
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO parser_errors (
                    error_id, event_time, sensor, raw_message, error_message
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    identifier,
                    to_iso(event_time or utc_now()),
                    sensor,
                    raw_message,
                    error_message,
                ),
            )
        return identifier

    def count(self) -> int:
        with self.database.connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM parser_errors").fetchone()
        return int(row["count"])

    def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM parser_errors ORDER BY event_time DESC LIMIT ?",
                (_limit(limit),),
            ).fetchall()
        return [dict(row) for row in rows]


class HealthRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert(self, health: HealthStatus) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO component_health (
                    component, status, last_success, last_error, details
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(component) DO UPDATE SET
                    status = excluded.status,
                    last_success = excluded.last_success,
                    last_error = excluded.last_error,
                    details = excluded.details
                """,
                (
                    health.component,
                    health.status.value,
                    to_iso(health.last_success),
                    health.last_error,
                    _json_dump(health.details),
                ),
            )

    def get(self, component: str) -> HealthStatus | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM component_health WHERE component = ?",
                (component,),
            ).fetchone()
        return _health_from_row(row) if row else None

    def list_all(self) -> list[HealthStatus]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM component_health ORDER BY component"
            ).fetchall()
        return [_health_from_row(row) for row in rows]


def _health_from_row(row: sqlite3.Row) -> HealthStatus:
    return HealthStatus(
        component=row["component"],
        status=HealthState(row["status"]),
        last_success=from_iso(row["last_success"]),
        last_error=row["last_error"],
        details=_json_load(row["details"]),
    )


class RepositorySet:
    """Conveniently construct repositories that share one Database."""

    def __init__(self, database: Database) -> None:
        self.auth_events = AuthenticationEventRepository(database)
        self.network_events = NetworkEventRepository(database)
        self.ip_profiles = IPProfileRepository(database)
        self.detections = DetectionRepository(database)
        self.allowlist = AllowlistRepository(database)
        self.blocks = BlockRepository(database)
        self.action_requests = ActionRequestRepository(database)
        self.audit = AuditRepository(database)
        self.parser_errors = ParserErrorRepository(database)
        self.health = HealthRepository(database)


__all__ = [
    "ActionRequestRepository",
    "AllowlistRepository",
    "AuditRepository",
    "AuthenticationEventRepository",
    "BlockRepository",
    "DetectionRepository",
    "HealthRepository",
    "IPProfileRepository",
    "NetworkEventRepository",
    "ParserErrorRepository",
    "RepositorySet",
    "from_iso",
    "to_iso",
    "utc_now",
]
