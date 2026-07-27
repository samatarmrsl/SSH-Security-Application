"""Structured application logging and database-backed security audit records."""

from __future__ import annotations

import json
import logging
import logging.handlers
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ssh_security_app.config import LoggingConfig
from ssh_security_app.db.repositories import AuditRepository
from ssh_security_app.models import AuditRecord


class JsonFormatter(logging.Formatter):
    """Emit one machine-readable JSON object per log line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True)


def configure_logging(config: LoggingConfig) -> None:
    """Configure console and rotating-file handlers once."""

    root = logging.getLogger()
    root.setLevel(config.level)
    formatter = JsonFormatter()

    console = logging.StreamHandler()
    console.setFormatter(formatter)

    log_path = Path(config.path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=config.max_bytes,
        backupCount=config.backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    root.handlers.clear()
    root.addHandler(console)
    root.addHandler(file_handler)


class AuditService:
    """Write a security audit record and a matching structured log entry."""

    def __init__(self, repository: AuditRepository) -> None:
        self.repository = repository
        self.logger = logging.getLogger("ssh_security_app.audit")

    def record(
        self,
        *,
        component: str,
        action: str,
        result: str,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        record = AuditRecord(
            audit_id=str(uuid.uuid4()),
            event_time=datetime.now(timezone.utc),
            component=component,
            action=action,
            target=target,
            result=result,
            details=details or {},
        )
        try:
            self.repository.insert(record)
        except Exception:
            self.logger.exception(
                "audit persistence failed: component=%s action=%s target=%s",
                component,
                action,
                target,
            )
            raise
        self.logger.info(
            "audit: component=%s action=%s target=%s result=%s details=%s",
            component,
            action,
            target,
            result,
            json.dumps(record.details, sort_keys=True, default=str),
        )
        return record.audit_id
