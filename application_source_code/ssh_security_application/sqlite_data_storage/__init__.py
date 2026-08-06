"""SQLite persistence package."""

from ssh_security_application.sqlite_data_storage.storage import (
    Database,
    DatabaseError,
)

__all__ = ["Database", "DatabaseError"]
