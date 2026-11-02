"""Signed one-time X25519 prekeys for forward-secrecy-oriented OIX envelopes.

Each recipient prekey is consumed atomically after successful authenticated
decryption. This module is transport-independent and opens no network sockets.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import canonical_json
from .envelope import MAX_MESSAGE_BYTES, verify_for_recipient
from .identity import fingerprint

PREKEY_VERSION = "1.0"
MAX_BUNDLE_TTL = 604800
MAX_PREKEYS_PER_BUNDLE = 100
MAX_PREKEY_ENVELOPE_BYTES = 1_100_000


class PreKeyError(ValueError):
    """A prekey bundle or encrypted message failed validation."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise PreKeyError("base64 field must be a non-empty string")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise PreKeyError("invalid base64 field") from exc


def _prekey_id(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()


def _derive_key(
    shared_secret: bytes,
    sender: str,
    recipient: str,
    key_id: str,
    ephemeral_public_raw: bytes,
) -> bytes:
    salt = hashlib.sha256(
        canonical_json({
            "sender": sender,
            "recipient": recipient,
            "prekey_id": key_id,
            "ephemeral_public_key": _b64(ephemeral_public_raw),
        })
    ).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"OIX/one-time-prekey/" + PREKEY_VERSION.encode("ascii"),
    ).derive(shared_secret)


def create_prekey_bundle(
    store: "SQLitePreKeyStore",
    signing_private_key: Ed25519PrivateKey,
    *,
    count: int = 20,
    ttl_seconds: int = MAX_BUNDLE_TTL,
    now: int | None = None,
) -> dict[str, Any]:
    """Generate and sign a public prekey bundle; private keys remain in local storage."""
    if not 1 <= count <= MAX_PREKEYS_PER_BUNDLE:
        raise ValueError("count must be between 1 and 100")
    if not 1 <= ttl_seconds <= MAX_BUNDLE_TTL:
        raise ValueError("ttl_seconds must be between 1 and 604800")
    if not isinstance(signing_private_key, Ed25519PrivateKey):
        raise TypeError("signing_private_key must be an Ed25519PrivateKey")
    issued_at = int(time.time()) if now is None else now
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0:
        raise ValueError("now must be a non-negative integer timestamp")

    keys: list[dict[str, str]] = []
    private_records: list[tuple[str, bytes, bytes, int]] = []
    for _ in range(count):
        private_key = X25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        key_id = _prekey_id(public_raw)
        keys.append({"key_id": key_id, "public_key": _b64(public_raw)})
        private_records.append((key_id, private_raw, public_raw, issued_at + ttl_seconds))

    body = {
        "protocol": "OIX",
        "version": PREKEY_VERSION,
        "agent_id": fingerprint(signing_private_key.public_key().public_bytes_raw()),
        "algorithm": "X25519",
        "created_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        "keys": keys,
    }
    signature = signing_private_key.sign(canonical_json(body))
    store.add_prekeys(private_records)
    return {"body": body, "signature": _b64(signature)}


def verify_prekey_bundle(
    bundle: dict[str, Any],
    trusted_signing_public_key: bytes,
    *,
    now: int | None = None,
) -> bool:
    try:
        if not isinstance(bundle, dict) or set(bundle) != {"body", "signature"}:
            return False
        body = bundle["body"]
        required = {
            "protocol", "version", "agent_id", "algorithm",
            "created_at", "expires_at", "keys",
        }
        if not isinstance(body, dict) or set(body) != required:
            return False
        if (
            body["protocol"] != "OIX"
            or body["version"] != PREKEY_VERSION
            or body["algorithm"] != "X25519"
            or body["agent_id"] != fingerprint(trusted_signing_public_key)
        ):
            return False
        created_at, expires_at = body["created_at"], body["expires_at"]
        current = int(time.time()) if now is None else now
        if (
            not isinstance(created_at, int) or isinstance(created_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or created_at < 0 or created_at > current + 60
            or expires_at < current
            or not 1 <= expires_at - created_at <= MAX_BUNDLE_TTL
        ):
            return False
        keys = body["keys"]
        if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_PREKEYS_PER_BUNDLE:
            return False
        seen: set[str] = set()
        for item in keys:
            if not isinstance(item, dict) or set(item) != {"key_id", "public_key"}:
                return False
            public_raw = _unb64(item["public_key"])
            if len(public_raw) != 32 or item["key_id"] != _prekey_id(public_raw):
                return False
            if item["key_id"] in seen:
                return False
            seen.add(item["key_id"])
        Ed25519PublicKey.from_public_bytes(trusted_signing_public_key).verify(
            _unb64(bundle["signature"]), canonical_json(body)
        )
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature, binascii.Error):
        return False

def encrypt_prekey_envelope(
    envelope: dict[str, Any],
    recipient_bundle: dict[str, Any],
    recipient_signing_public_key: bytes,
    *,
    key_id: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Encrypt an already-signed OIX message to one public one-time prekey."""
    if not verify_prekey_bundle(recipient_bundle, recipient_signing_public_key, now=now):
        raise PreKeyError("recipient prekey bundle is invalid or expired")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("body"), dict):
        raise PreKeyError("inner OIX message is malformed")
    body = envelope["body"]
    sender, recipient = body.get("sender"), body.get("recipient")
    recipient_id = recipient_bundle["body"]["agent_id"]
    if not isinstance(sender, str) or not sender or recipient != recipient_id:
        raise PreKeyError("inner OIX sender or recipient is invalid")
    keys = recipient_bundle["body"]["keys"]
    selected = next(
        (item for item in keys if item["key_id"] == key_id),
        None,
    ) if key_id is not None else keys[0]
    if selected is None:
        raise PreKeyError("requested one-time prekey is not in the signed bundle")
    public_raw = _unb64(selected["public_key"])
    if len(public_raw) != 32:
        raise PreKeyError("recipient prekey public key is invalid")
    plaintext = canonical_json(envelope)
    if len(plaintext) > MAX_MESSAGE_BYTES:
        raise PreKeyError("inner OIX message exceeds the 1 MB limit")
    issued_at = int(time.time()) if now is None else now
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0:
        raise ValueError("now must be a non-negative integer timestamp")

    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_raw = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    nonce = os.urandom(12)
    header = {
        "protocol": "OIX",
        "version": PREKEY_VERSION,
        "mode": "one_time_prekey",
        "sender": sender,
        "recipient": recipient_id,
        "prekey_id": selected["key_id"],
        "prekey_fingerprint": _prekey_id(public_raw),
        "ephemeral_public_key": _b64(ephemeral_public_raw),
        "nonce": _b64(nonce),
        "issued_at": issued_at,
    }
    key = _derive_key(
        ephemeral_private.exchange(X25519PublicKey.from_public_bytes(public_raw)),
        sender,
        recipient_id,
        selected["key_id"],
        ephemeral_public_raw,
    )
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, canonical_json(header))
    result = {"header": header, "ciphertext": _b64(ciphertext)}
    if len(canonical_json(result)) > MAX_PREKEY_ENVELOPE_BYTES:
        raise PreKeyError("encrypted envelope exceeds the 1.1 MB limit")
    return result


class SQLitePreKeyStore:
    """Local owner-only store; a prekey is deleted only after successful decryption."""

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        path = Path(self.database)
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError("prekey database path must not traverse a symlink")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            try:
                descriptor = os.open(self.database, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                os.chmod(path, 0o600)
            else:
                os.close(descriptor)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA secure_delete=ON")
            db.execute("""
                CREATE TABLE IF NOT EXISTS one_time_prekeys (
                    key_id TEXT PRIMARY KEY,
                    private_key BLOB NOT NULL,
                    public_key BLOB NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('available','consumed'))
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA secure_delete=ON")
        return db

    def add_prekeys(
        self, records: list[tuple[str, bytes, bytes, int]]
    ) -> None:
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            for key_id, private_raw, public_raw, expires_at in records:
                if len(private_raw) != 32 or len(public_raw) != 32:
                    raise PreKeyError("prekey material must be exactly 32 bytes")
                if key_id != _prekey_id(public_raw):
                    raise PreKeyError("prekey ID does not match public key")
                db.execute(
                    """INSERT INTO one_time_prekeys(
                        key_id,private_key,public_key,expires_at,created_at,status
                    ) VALUES(?,?,?,?,?,'available')""",
                    (key_id, private_raw, public_raw, expires_at, int(time.time())),
                )
            db.commit()

    def available_count(self, *, now: int) -> int:
        with closing(self._connect()) as db:
            return db.execute(
                "SELECT COUNT(*) FROM one_time_prekeys WHERE status='available' AND expires_at>=?",
                (now,),
            ).fetchone()[0]

    def consume_and_decrypt(
        self,
        secure_envelope: dict[str, Any],
        recipient_signing_public_key: bytes,
        sender_signing_public_key: bytes,
        local_agent_id: str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Atomically decrypt and consume a prekey exactly once after validation."""
        current = int(time.time()) if now is None else now
        if not isinstance(secure_envelope, dict) or set(secure_envelope) != {"header", "ciphertext"}:
            raise PreKeyError("encrypted envelope has an invalid shape")
        if len(canonical_json(secure_envelope)) > MAX_PREKEY_ENVELOPE_BYTES:
            raise PreKeyError("encrypted envelope exceeds the 1.1 MB limit")
        header = secure_envelope["header"]
        required = {
            "protocol", "version", "mode", "sender", "recipient", "prekey_id",
            "prekey_fingerprint", "ephemeral_public_key", "nonce", "issued_at",
        }
        if not isinstance(header, dict) or set(header) != required:
            raise PreKeyError("encrypted envelope header has an invalid shape")
        issued_at = header["issued_at"]
        if (
            header["protocol"] != "OIX" or header["version"] != PREKEY_VERSION
            or header["mode"] != "one_time_prekey"
            or header["recipient"] != local_agent_id
            or header["sender"] != fingerprint(sender_signing_public_key)
            or not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or issued_at < 0 or issued_at > current + 60
        ):
            raise PreKeyError("encrypted envelope route, sender, or timestamp is invalid")
        ephemeral_raw = _unb64(header["ephemeral_public_key"])
        nonce = _unb64(header["nonce"])
        ciphertext = _unb64(secure_envelope["ciphertext"])
        if len(ephemeral_raw) != 32 or len(nonce) != 12:
            raise PreKeyError("invalid ephemeral public key or nonce length")

        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT private_key,public_key,expires_at,status "
                "FROM one_time_prekeys WHERE key_id=?",
                (header["prekey_id"],),
            ).fetchone()
            if row is None or row["status"] != "available":
                raise PreKeyError("one-time prekey is missing or already consumed")
            if issued_at > row["expires_at"]:
                raise PreKeyError("message was created after the prekey expired")
            public_raw = bytes(row["public_key"])
            if (
                _prekey_id(public_raw) != header["prekey_id"]
                or header["prekey_fingerprint"] != _prekey_id(public_raw)
            ):
                raise PreKeyError("prekey fingerprint mismatch")
            private_key = X25519PrivateKey.from_private_bytes(bytes(row["private_key"]))
            key = _derive_key(
                private_key.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw)),
                header["sender"],
                header["recipient"],
                header["prekey_id"],
                ephemeral_raw,
            )
            try:
                plaintext = ChaCha20Poly1305(key).decrypt(
                    nonce, ciphertext, canonical_json(header)
                )
            except InvalidTag as exc:
                raise PreKeyError("encrypted envelope authentication failed") from exc
            try:
                inner = json.loads(plaintext)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PreKeyError("decrypted message is not valid JSON") from exc
            if (
                not isinstance(inner, dict)
                or not isinstance(inner.get("body"), dict)
                or inner["body"].get("sender") != header["sender"]
                or not verify_for_recipient(
                    inner, sender_signing_public_key, local_agent_id, now=current
                )
            ):
                raise PreKeyError("inner OIX signature, sender, or recipient validation failed")
            db.execute(
                "DELETE FROM one_time_prekeys WHERE key_id=? AND status='available'",
                (header["prekey_id"],),
            )
            db.commit()
            return inner
