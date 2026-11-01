"""Signed OIX message envelope."""
from __future__ import annotations

import base64
import json
import time
import uuid
import secrets
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json
from .identity import fingerprint

MAX_MESSAGE_BYTES = 1_000_000
ALLOWED_TYPES = {
    "agent.hello", "agent.hello_ack", "task.request", "task.accepted",
    "task.progress", "task.result", "evidence.submit", "error",
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_message(
    private_key: Ed25519PrivateKey,
    recipient: str,
    message_type: str,
    payload: dict[str, Any],
    *,
    ttl_seconds: int = 300,
    capability: str | None = None,
) -> dict[str, Any]:
    if message_type not in ALLOWED_TYPES:
        raise ValueError("unsupported message_type")
    if not 1 <= ttl_seconds <= 86_400:
        raise ValueError("ttl_seconds must be between 1 and 86400")
    public_raw = private_key.public_key().public_bytes_raw()
    now = int(time.time())
    body = {
        "protocol": "OIX",
        "version": "0.1",
        "message_id": str(uuid.uuid4()),
        "sender": fingerprint(public_raw),
        "recipient": recipient,
        "type": message_type,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "nonce": secrets.token_urlsafe(24),
        "requested_capability": capability,
        "payload": payload,
    }
    signature = private_key.sign(canonical_json(body))
    envelope = {"body": body, "signature": _b64(signature)}
    if len(canonical_json(envelope)) > MAX_MESSAGE_BYTES:
        raise ValueError("message exceeds 1 MB limit")
    return envelope


def verify_message(envelope: dict[str, Any], public_key: bytes, *, now: int | None = None) -> bool:
    try:
        if len(canonical_json(envelope)) > MAX_MESSAGE_BYTES:
            return False
        body = envelope["body"]
        if not isinstance(body, dict) or not isinstance(body.get("payload"), dict):
            return False
        if body.get("protocol") != "OIX" or body.get("version") != "0.1":
            return False
        if body.get("type") not in ALLOWED_TYPES:
            return False
        if not isinstance(body.get("recipient"), str) or not body["recipient"]:
            return False
        if not isinstance(body.get("message_id"), str) or not isinstance(body.get("nonce"), str):
            return False
        if not 20 <= len(body["nonce"]) <= 128:
            return False
        if body.get("sender") != fingerprint(public_key):
            return False
        current = int(time.time()) if now is None else now
        if (not isinstance(body.get("issued_at"), int) or isinstance(body["issued_at"], bool)
                or not isinstance(body.get("expires_at"), int) or isinstance(body["expires_at"], bool)):
            return False
        if body["issued_at"] > current + 60 or body["expires_at"] < current:
            return False
        if body["expires_at"] <= body["issued_at"]:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _unb64(envelope["signature"]), canonical_json(body)
        )
        return True
    except Exception:
        return False


def write_message(envelope: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(envelope, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
