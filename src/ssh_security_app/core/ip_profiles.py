"""Read contextual history for observed source addresses."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ssh_security_app.db.repositories import BlockRepository, IPProfileRepository, from_iso


class IPProfileManager:
    def __init__(
        self,
        profiles: IPProfileRepository,
        blocks: BlockRepository,
    ) -> None:
        self.profiles = profiles
        self.blocks = blocks

    def get_profile(self, source_ip: str) -> dict[str, Any] | None:
        profile = self.profiles.get(source_ip)
        if profile is None:
            return None
        active_block = self.blocks.get_active(source_ip)
        return {
            **profile,
            "currently_blocked": active_block is not None,
            "active_block_id": active_block.block_id if active_block else None,
        }

    def has_recent_success(
        self,
        source_ip: str,
        *,
        at: datetime,
        recent_success_days: int,
    ) -> bool:
        profile = self.profiles.get(source_ip)
        if profile is None or profile["last_success_at"] is None:
            return False
        reference = at.astimezone(timezone.utc)
        last_success = from_iso(profile["last_success_at"])
        if last_success is None:
            return False
        return last_success >= reference - timedelta(days=recent_success_days)
