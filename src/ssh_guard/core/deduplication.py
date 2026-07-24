"""Small thread-safe duplicate cache for live collector pipelines."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone


class EventDeduplicator:
    """Remember stable fingerprints for a short configurable window."""

    def __init__(self, window_seconds: int = 5) -> None:
        if window_seconds < 1:
            raise ValueError("duplicate window must be at least one second")
        self.window = timedelta(seconds=window_seconds)
        self._seen: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def is_duplicate(self, fingerprint: str, *, observed_at: datetime | None = None) -> bool:
        now = observed_at or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        now = now.astimezone(timezone.utc)
        cutoff = now - self.window
        with self._lock:
            self._seen = {
                key: timestamp for key, timestamp in self._seen.items() if timestamp >= cutoff
            }
            previous = self._seen.get(fingerprint)
            self._seen[fingerprint] = now
        return previous is not None and previous >= cutoff

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
