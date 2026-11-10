"""Signed, expiring OIX discovery announcements.

Discovery is separate from trust and authorization. This module records
signed endpoint hints; it never fetches an endpoint or enrolls a peer.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json, decode_base64url
from .identity import fingerprint, verify_card

MAX_TTL_SECONDS = 3600
MAX_FUTURE_SKEW_SECONDS = 60
MAX_ENDPOINTS = 8
MAX_ENDPOINT_LENGTH = 2048
_CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class DiscoveryError(ValueError):
    """A discovery announcement is invalid, stale, or replayed."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return decode_base64url(value)


def _validate_timestamp(value: Any, field: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DiscoveryError(f"{field} must be a non-negative integer timestamp")


def _validate_endpoint(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_ENDPOINT_LENGTH:
        raise DiscoveryError("endpoint must be a non-empty bounded URL")
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        raise DiscoveryError("endpoint contains whitespace or control characters")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise DiscoveryError("endpoint URL is malformed") from exc
    if (parsed.scheme != "https" or not hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise DiscoveryError("endpoint must be HTTPS with a host and no credentials or fragment")
    return value


def create_announcement(
    private_key: Ed25519PrivateKey,
    signed_card: dict[str, Any],
    endpoints: list[str],
    *,
    sequence: int,
    now: int,
    ttl: int = 300,
) -> dict[str, Any]:
    """Create an Ed25519-signed endpoint announcement bound to a signed agent card."""
    if not verify_card(signed_card):
        raise DiscoveryError("agent card signature is invalid")
    _validate_timestamp(now, "now")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise DiscoveryError("sequence must be a positive integer")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= MAX_TTL_SECONDS:
        raise DiscoveryError(f"ttl must be between 1 and {MAX_TTL_SECONDS} seconds")
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= MAX_ENDPOINTS:
        raise DiscoveryError(f"one to {MAX_ENDPOINTS} endpoints are required")
    checked_endpoints = [_validate_endpoint(item) for item in endpoints]
    if len(set(checked_endpoints)) != len(checked_endpoints):
        raise DiscoveryError("duplicate endpoints are not allowed")

    card = signed_card["card"]
    public_raw = _unb64(card["public_key"])
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if private_public != public_raw:
        raise DiscoveryError("private key does not match the signed agent card")
    capabilities = card["capabilities"]
    if (not isinstance(capabilities, list)
            or any(not isinstance(item, str) or not _CAPABILITY.fullmatch(item) for item in capabilities)
            or len(set(capabilities)) != len(capabilities)):
        raise DiscoveryError("agent card capabilities are malformed")

    body = {
        "protocol": "OIX",
        "protocol_version": "0.1",
        "agent_id": fingerprint(public_raw),
        "sequence": sequence,
        "announcement_id": str(uuid.uuid4()),
        "issued_at": now,
        "expires_at": now + ttl,
        "card_sha256": hashlib.sha256(canonical_json(signed_card)).hexdigest(),
        "endpoints": checked_endpoints,
        "capabilities": sorted(capabilities),
    }
    return {"announcement": body, "signature": _b64(private_key.sign(canonical_json(body)))}


def verify_announcement(
    signed_announcement: dict[str, Any],
    signed_card: dict[str, Any],
    *,
    now: int,
) -> bool:
    """Verify signature, identity binding, expiry, endpoint syntax, and card claims."""
    try:
        _validate_timestamp(now, "now")
        if not verify_card(signed_card):
            return False
        if not isinstance(signed_announcement, dict) or set(signed_announcement) != {
            "announcement", "signature"
        }:
            return False
        body = signed_announcement["announcement"]
        required = {
            "protocol", "protocol_version", "agent_id", "sequence", "announcement_id",
            "issued_at", "expires_at", "card_sha256", "endpoints", "capabilities",
        }
        if not isinstance(body, dict) or set(body) != required:
            return False
        card = signed_card["card"]
        public_raw = _unb64(card["public_key"])
        if (body["protocol"] != "OIX" or body["protocol_version"] != "0.1"
                or body["agent_id"] != fingerprint(public_raw)
                or body["card_sha256"] != hashlib.sha256(canonical_json(signed_card)).hexdigest()):
            return False
        if (not isinstance(body["sequence"], int) or isinstance(body["sequence"], bool)
                or body["sequence"] < 1):
            return False
        _validate_timestamp(body["issued_at"], "issued_at")
        _validate_timestamp(body["expires_at"], "expires_at")
        if (not isinstance(body["announcement_id"], str)
                or str(uuid.UUID(body["announcement_id"])) != body["announcement_id"]):
            return False
        ttl = body["expires_at"] - body["issued_at"]
        if not 1 <= ttl <= MAX_TTL_SECONDS:
            return False
        if body["issued_at"] > now + MAX_FUTURE_SKEW_SECONDS or body["expires_at"] <= now:
            return False
        endpoints = body["endpoints"]
        if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= MAX_ENDPOINTS:
            return False
        checked = [_validate_endpoint(item) for item in endpoints]
        if len(set(checked)) != len(checked):
            return False
        capabilities = body["capabilities"]
        card_capabilities = card["capabilities"]
        if (not isinstance(capabilities, list) or capabilities != sorted(set(capabilities))
                or any(not isinstance(item, str) or not _CAPABILITY.fullmatch(item) for item in capabilities)
                or not set(capabilities).issubset(set(card_capabilities))):
            return False
        signature = _unb64(signed_announcement["signature"])
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, canonical_json(body))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError,
            binascii.Error, OverflowError):
        return False


class SQLiteDiscoveryStore:
    """Persist latest signed announcements while keeping every peer untrusted."""

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        path = Path(self.database)
        if path.is_symlink() or path.parent.is_symlink():
            raise DiscoveryError("discovery database path must not traverse a symlink")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            try:
                descriptor = os.open(self.database, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                os.chmod(path, 0o600)
            else:
                os.close(descriptor)
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS discovery_announcements (
                    agent_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    announcement_json TEXT NOT NULL,
                    card_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    received_at INTEGER NOT NULL,
                    trust_state TEXT NOT NULL CHECK(trust_state='discovered_untrusted')
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def record(self, signed_announcement: dict[str, Any], signed_card: dict[str, Any],
               *, now: int) -> str:
        if not verify_announcement(signed_announcement, signed_card, now=now):
            raise DiscoveryError("announcement failed verification")
        body = signed_announcement["announcement"]
        agent_id = body["agent_id"]
        encoded = json.dumps(signed_announcement, sort_keys=True, separators=(",", ":"))
        card_encoded = json.dumps(signed_card, sort_keys=True, separators=(",", ":"))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT sequence FROM discovery_announcements WHERE agent_id=?", (agent_id,)
            ).fetchone()
            if previous is not None and body["sequence"] <= previous["sequence"]:
                raise DiscoveryError("announcement replay or sequence rollback rejected")
            db.execute(
                """INSERT INTO discovery_announcements(
                    agent_id,sequence,announcement_json,card_json,expires_at,received_at,trust_state
                ) VALUES(?,?,?,?,?,?,'discovered_untrusted')
                ON CONFLICT(agent_id) DO UPDATE SET
                    sequence=excluded.sequence, announcement_json=excluded.announcement_json,
                    card_json=excluded.card_json, expires_at=excluded.expires_at,
                    received_at=excluded.received_at, trust_state='discovered_untrusted'""",
                (agent_id, body["sequence"], encoded, card_encoded, body["expires_at"], now),
            )
            db.commit()
        return agent_id

    def active(self, *, now: int) -> list[dict[str, Any]]:
        _validate_timestamp(now, "now")
        with self._connect() as db:
            rows = db.execute(
                """SELECT agent_id,sequence,announcement_json,card_json,expires_at,
                          received_at,trust_state FROM discovery_announcements
                   WHERE expires_at>? ORDER BY agent_id""", (now,)
            ).fetchall()
        return [{
            "agent_id": row["agent_id"], "sequence": row["sequence"],
            "announcement": json.loads(row["announcement_json"]),
            "card": json.loads(row["card_json"]), "expires_at": row["expires_at"],
            "received_at": row["received_at"], "trust_state": row["trust_state"],
        } for row in rows]
