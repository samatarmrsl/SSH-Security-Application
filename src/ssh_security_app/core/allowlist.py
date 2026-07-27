"""Validated allowlist management with audit records."""

from __future__ import annotations

import ipaddress
from datetime import datetime

from ssh_security_app.audit import AuditService
from ssh_security_app.db.repositories import AllowlistRepository


class AllowlistManager:
    def __init__(self, repository: AllowlistRepository, audit: AuditService) -> None:
        self.repository = repository
        self.audit = audit

    def add_allowlist_entry(
        self,
        *,
        ip_address: str,
        description: str,
        reason: str,
        created_by: str,
        expires_at: datetime | None = None,
        notes: str | None = None,
    ) -> str:
        normalized = _validated_ipv4(ip_address)
        entry_id = self.repository.add(
            ip_address=normalized,
            description=description,
            reason=reason,
            created_by=created_by,
            expires_at=expires_at,
            notes=notes,
        )
        self.audit.record(
            component="allowlist",
            action="allowlist_addition",
            target=normalized,
            result="success",
            details={"allowlist_id": entry_id, "reason": reason, "created_by": created_by},
        )
        return entry_id

    def disable_allowlist_entry(self, allowlist_id: str) -> bool:
        entry = self.repository.get(allowlist_id)
        changed = self.repository.disable(allowlist_id)
        self.audit.record(
            component="allowlist",
            action="allowlist_disable",
            target=entry["ip_address"] if entry else allowlist_id,
            result="success" if changed else "not_found_or_inactive",
            details={"allowlist_id": allowlist_id},
        )
        return changed

    def get_allowlist_entry(self, allowlist_id: str) -> dict[str, object] | None:
        return self.repository.get(allowlist_id)

    def is_allowlisted(self, ip_address: str, *, at: datetime | None = None) -> bool:
        try:
            normalized = _validated_ipv4(ip_address)
        except ValueError:
            return False
        return self.repository.is_allowlisted(normalized, at=at)

    def list_active_entries(
        self,
        *,
        at: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        return self.repository.list_active(at=at, limit=limit)

    def expire_old_entries(self, *, at: datetime | None = None) -> int:
        count = self.repository.expire_old(at=at)
        if count:
            self.audit.record(
                component="allowlist",
                action="allowlist_expiration",
                result="success",
                details={"expired_count": count},
            )
        return count


def _validated_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except (AttributeError, ipaddress.AddressValueError) as exc:
        raise ValueError(f"allowlist address must be valid IPv4: {value!r}") from exc
