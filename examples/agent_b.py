"""Minimal receiver-side verification example; no network listener is opened."""
from __future__ import annotations

from oix.policy import CapabilityPolicy


def authorize_message(message_body: dict, policy: CapabilityPolicy, local_agent_id: str) -> bool:
    """Apply recipient and capability checks after cryptographic verification."""
    return (
        message_body.get("recipient") == local_agent_id
        and policy.permits(message_body.get("requested_capability"))
    )
