"""Protocol-version and capability negotiation helpers."""
from __future__ import annotations
from typing import Any

def negotiate(local_versions: list[str], remote_card: dict[str, Any], required_capabilities: set[str] | None = None) -> dict[str, Any]:
    """Choose a mutually supported version and check advertised capabilities.

    The caller must verify the remote card signature before relying on its contents.
    """
    card = remote_card.get("card", remote_card)
    remote_version = card.get("protocol_version")
    common = sorted(set(local_versions) & {remote_version})
    if not common:
        return {"accepted": False, "reason": "no_common_protocol_version"}
    available = set(card.get("capabilities", []))
    required = set(required_capabilities or ())
    missing = sorted(required - available)
    if missing:
        return {"accepted": False, "reason": "missing_capabilities", "missing": missing}
    return {"accepted": True, "protocol": "OIX", "version": common[-1],
            "peer": card.get("agent_id"),
            "capabilities": sorted(available & required) if required else sorted(available)}
