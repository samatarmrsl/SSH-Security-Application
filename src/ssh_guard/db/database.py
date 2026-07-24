"""SQLite connection and transaction management."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class DatabaseError(RuntimeError):
    """Raised when a database operation cannot be completed."""


class Database:
    """Create consistently configured short-lived SQLite connections."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_seconds: int = 5,
        wal_mode: bool = True,
    ) -> None:
        self.path = Path(path)
        self.busy_timeout_seconds = busy_timeout_seconds
        self.wal_mode = wal_mode

    def connect(self) -> sqlite3.Connection:
        """Open a connection with project safety pragmas enabled."""

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=self.busy_timeout_seconds)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            timeout_ms = self.busy_timeout_seconds * 1000
            connection.execute(f"PRAGMA busy_timeout = {timeout_ms:d}")
            if self.wal_mode:
                connection.execute("PRAGMA journal_mode = WAL")
            return connection
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError(f"could not open SQLite database at {self.path}: {exc}") from exc

    def initialize(self) -> None:
        """Create all tables and indexes without changing existing data."""

        try:
            schema = SCHEMA_PATH.read_text(encoding="utf-8")
            with self.connect() as connection:
                connection.executescript(schema)
                connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError(f"could not initialize SQLite database: {exc}") from exc

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit on success and roll back on failure."""

        connection = self.connect()
        try:
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def check_health(self) -> bool:
        try:
            with self.connection() as connection:
                row = connection.execute("SELECT 1 AS healthy").fetchone()
            return bool(row and row["healthy"] == 1)
        except DatabaseError:
            return False
