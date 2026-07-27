"""SQLite persistence package."""

from ssh_security_app.db.database import Database, DatabaseError

__all__ = ["Database", "DatabaseError"]
