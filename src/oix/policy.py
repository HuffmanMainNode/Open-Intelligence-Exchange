"""Least-privilege capability policy. This module authorizes labels, not actions."""
from __future__ import annotations


class CapabilityPolicy:
    def __init__(self, allowed: set[str] | None = None) -> None:
        self.allowed = set(allowed or ())

    def permits(self, requested: str | None, *, message_type: str | None = None) -> bool:
        if requested is None:
            return message_type not in {"task.request", "evidence.submit"}
        return requested in self.allowed
