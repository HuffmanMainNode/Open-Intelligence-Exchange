"""Least-privilege capability policy. This module authorizes labels, not actions."""
from __future__ import annotations


class CapabilityPolicy:
    def __init__(self, allowed: set[str] | None = None) -> None:
        self.allowed = set(allowed or ())

    def permits(self, requested: str | None) -> bool:
        return requested is None or requested in self.allowed
