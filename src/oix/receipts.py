"""Signed, content-bound acknowledgements for durable OIX message acceptance."""
from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json
from .envelope import create_message, verify_message
from .identity import fingerprint


class DeliveryReceiptError(ValueError):
    """A delivery receipt does not authenticate the expected durable acceptance."""


def message_digest(envelope: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(envelope)).hexdigest()


def create_delivery_receipt(
    recipient_private_key: Ed25519PrivateKey,
    original_sender_agent_id: str,
    accepted_envelope: dict[str, Any],
    *,
    accepted_at: int,
) -> dict[str, Any]:
    """Create a signed receipt only after the receiver durably accepts a message."""
    body = accepted_envelope.get("body", {}) if isinstance(accepted_envelope, dict) else {}
    if body.get("recipient") != fingerprint(
        recipient_private_key.public_key().public_bytes_raw()
    ):
        raise DeliveryReceiptError("accepted message was not addressed to this receipt signer")
    return create_message(
        recipient_private_key,
        original_sender_agent_id,
        "delivery.receipt",
        {
            "acknowledged_message_id": body.get("message_id"),
            "acknowledged_message_digest": message_digest(accepted_envelope),
            "accepted_at": accepted_at,
            "durable": True,
            "status": "accepted",
        },
    )


def verify_delivery_receipt(
    receipt: dict[str, Any],
    recipient_signing_public_key: bytes,
    *,
    expected_recipient_agent_id: str,
    expected_sender_agent_id: str,
    expected_message_id: str,
    expected_message_digest: str,
    now: int | None = None,
) -> bool:
    """Verify signer, route, signature, expiry, exact message ID and content digest."""
    if not verify_message(receipt, recipient_signing_public_key, now=now):
        return False
    body = receipt.get("body", {})
    payload = body.get("payload", {})
    return (
        body.get("type") == "delivery.receipt"
        and body.get("sender") == expected_recipient_agent_id
        and body.get("recipient") == expected_sender_agent_id
        and payload.get("acknowledged_message_id") == expected_message_id
        and payload.get("acknowledged_message_digest") == expected_message_digest
        and payload.get("durable") is True
        and payload.get("status") == "accepted"
        and isinstance(payload.get("accepted_at"), int)
        and not isinstance(payload.get("accepted_at"), bool)
    )
