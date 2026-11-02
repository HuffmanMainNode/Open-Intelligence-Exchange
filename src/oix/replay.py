"""Bounded in-memory replay protection. Persisted deployments need durable storage."""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any


class ReplayCache:
    def __init__(self, max_entries: int = 100_000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._seen: OrderedDict[tuple[str, str], int] = OrderedDict()

    def accept(self, body: dict[str, Any], *, now: int | None = None) -> bool:
        current = int(time.time()) if now is None else now
        self._seen = OrderedDict(
            (key, expiry) for key, expiry in self._seen.items() if expiry >= current
        )
        key = (body["sender"], body["nonce"])
        if key in self._seen or body["expires_at"] < current:
            return False
        if len(self._seen) >= self.max_entries:
            return False
        self._seen[key] = body["expires_at"]
        return True
