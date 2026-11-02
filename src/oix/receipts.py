"""Signed, content-bound acknowledgements for durable OIX message acceptance."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json
from .envelope import create_message, verify_message


def message_digest(envelope: dict[str, Any]) -> str:
    """Return the SHA-256 digest of the canonical transport envelope."""
    return hashlib.sha256(canonical_json(envelope)).hexdigest()


class DeliveryReceiptError(ValueError):
    """A delivery receipt does not authenticate the expected durable acceptance."""


def create_delivery_receipt(
    recipient_private_key: Ed25519PrivateKey,
    original_sender_agent_id: str,
    acknowledged_message_id: str,
    acknowledged_content_digest: str,
    *,
    accepted_at: int,
) -> dict[str, Any]:
    """Create a signed receipt after the exact transport payload is durably stored."""
    if not isinstance(acknowledged_message_id, str) or not acknowledged_message_id:
        raise DeliveryReceiptError("acknowledged_message_id is required")
    if not isinstance(acknowledged_content_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", acknowledged_content_digest
    ):
        raise DeliveryReceiptError("acknowledged_content_digest must be a SHA-256 hex digest")
    if not isinstance(accepted_at, int) or isinstance(accepted_at, bool) or accepted_at < 0:
        raise DeliveryReceiptError("accepted_at must be a non-negative integer")
    return create_message(
        recipient_private_key,
        original_sender_agent_id,
        "delivery.receipt",
        {
            "acknowledged_message_id": acknowledged_message_id,
            "acknowledged_content_digest": acknowledged_content_digest,
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
    expected_content_digest: str,
    now: int | None = None,
) -> bool:
    """Verify signer, route, signature, expiry, exact message ID and content digest."""
    if not verify_message(receipt, recipient_signing_public_key, now=now):
        return False
    body = receipt.get("body", {})
    payload = body.get("payload", {})
    if not isinstance(body, dict) or set(body) != {
        "protocol", "version", "message_id", "sender", "recipient", "type",
        "issued_at", "expires_at", "nonce", "requested_capability", "payload",
    }:
        return False
    if not isinstance(payload, dict) or set(payload) != {
        "acknowledged_message_id", "acknowledged_content_digest",
        "accepted_at", "durable", "status",
    }:
        return False
    return (
        body.get("type") == "delivery.receipt"
        and body.get("sender") == expected_recipient_agent_id
        and body.get("recipient") == expected_sender_agent_id
        and payload.get("acknowledged_message_id") == expected_message_id
        and payload.get("acknowledged_content_digest") == expected_content_digest
        and payload.get("durable") is True
        and payload.get("status") == "accepted"
        and isinstance(payload.get("accepted_at"), int)
        and not isinstance(payload.get("accepted_at"), bool)
        and payload["accepted_at"] >= 0
    )
