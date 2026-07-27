from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ssh_security_app.audit import AuditService
from ssh_security_app.core.allowlist import AllowlistManager
from ssh_security_app.db.database import Database
from ssh_security_app.db.repositories import RepositorySet


def build_manager(tmp_path):
    database = Database(tmp_path / "allowlist.db")
    database.initialize()
    repositories = RepositorySet(database)
    manager = AllowlistManager(repositories.allowlist, AuditService(repositories.audit))
    return repositories, manager


def test_allowlist_lifecycle_is_validated_and_audited(tmp_path) -> None:
    repositories, manager = build_manager(tmp_path)
    entry_id = manager.add_allowlist_entry(
        ip_address="192.168.56.50",
        description="Lab administrator",
        reason="Authorized testing source",
        created_by="unit-test",
    )

    assert manager.is_allowlisted("192.168.56.50") is True
    assert manager.get_allowlist_entry(entry_id)["ip_address"] == "192.168.56.50"
    assert len(manager.list_active_entries()) == 1
    assert manager.disable_allowlist_entry(entry_id) is True
    assert manager.is_allowlisted("192.168.56.50") is False
    assert [record.action for record in repositories.audit.list_recent()] == [
        "allowlist_disable",
        "allowlist_addition",
    ]


def test_invalid_or_ipv6_allowlist_address_is_rejected(tmp_path) -> None:
    _, manager = build_manager(tmp_path)

    with pytest.raises(ValueError, match="valid IPv4"):
        manager.add_allowlist_entry(
            ip_address="2001:db8::1",
            description="invalid version",
            reason="test",
            created_by="unit-test",
        )

    assert manager.is_allowlisted("not-an-ip") is False


def test_expired_entry_is_disabled(tmp_path) -> None:
    _, manager = build_manager(tmp_path)
    now = datetime.now(timezone.utc)
    manager.add_allowlist_entry(
        ip_address="192.168.56.51",
        description="Temporary",
        reason="test",
        created_by="unit-test",
        expires_at=now,
    )

    assert manager.expire_old_entries(at=now) == 1
