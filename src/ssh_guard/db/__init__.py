"""SQLite persistence package."""

from ssh_guard.db.database import Database, DatabaseError

__all__ = ["Database", "DatabaseError"]
