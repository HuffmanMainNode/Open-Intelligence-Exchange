"""Authenticated-encryption wrapper for signed OIX envelopes.

This is a transport-independent confidentiality primitive. It does not open
sockets, perform peer discovery, or replace the inner Ed25519 message signature.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .canonical import canonical_json
from .envelope import MAX_MESSAGE_BYTES, verify_for_recipient
from .identity import fingerprint

_CERTIFICATE_FIELDS = {
    "protocol", "version", "agent_id", "algorithm", "public_key",
    "issued_at", "expires_at",
}
_HEADER_FIELDS = {
    "protocol", "version", "sender", "recipient",
    "recipient_key_fingerprint", "ephemeral_public_key", "nonce",
}
MAX_SECURE_ENVELOPE_BYTES = 1_100_000
MAX_CERTIFICATE_TTL = 2_592_000
SECURE_VERSION = "1.0"


class SecureEnvelopeError(ValueError):
    """An encrypted OIX envelope failed validation or authentication."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise SecureEnvelopeError("base64 field must be a non-empty string")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise SecureEnvelopeError("invalid base64 field") from exc


def generate_encryption_key(
    directory: str | Path,
    signing_private_key: Any,
    *,
    ttl_seconds: int = MAX_CERTIFICATE_TTL,
    now: int | None = None,
) -> dict[str, Any]:
    """Create a separate X25519 key and an Ed25519-signed public-key certificate."""
    if not 1 <= ttl_seconds <= MAX_CERTIFICATE_TTL:
        raise ValueError("ttl_seconds must be between 1 and 2592000")
    if not hasattr(signing_private_key, "sign") or not hasattr(signing_private_key, "public_key"):
        raise TypeError("signing_private_key must be an Ed25519 private key")
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(path, 0o700)
    private_path = path / "encryption.key"
    certificate_path = path / "encryption-certificate.json"
    if private_path.exists() or certificate_path.exists():
        raise FileExistsError("encryption key files already exist; refusing to overwrite")
    private_key = X25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    descriptor = os.open(private_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(private_raw)
    timestamp = int(time.time()) if now is None else now
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise ValueError("now must be a non-negative integer timestamp")
    body = {
        "protocol": "OIX",
        "version": SECURE_VERSION,
        "agent_id": fingerprint(
            signing_private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ),
        "algorithm": "X25519",
        "public_key": _b64(public_raw),
        "issued_at": timestamp,
        "expires_at": timestamp + ttl_seconds,
    }
    signature = signing_private_key.sign(canonical_json(body))
    certificate = {"body": body, "signature": _b64(signature)}
    with certificate_path.open("x", encoding="utf-8") as stream:
        json.dump(certificate, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return certificate


def load_encryption_private_key(directory: str | Path) -> X25519PrivateKey:
    raw = (Path(directory) / "encryption.key").read_bytes()
    if len(raw) != 32:
        raise SecureEnvelopeError("X25519 private key must contain exactly 32 bytes")
    return X25519PrivateKey.from_private_bytes(raw)


def verify_encryption_certificate(
    certificate: dict[str, Any],
    signing_public_key: bytes,
    *,
    now: int | None = None,
) -> bool:
    try:
        if not isinstance(certificate, dict) or set(certificate) != {"body", "signature"}:
            return False
        body = certificate["body"]
        if not isinstance(body, dict) or set(body) != _CERTIFICATE_FIELDS:
            return False
        if (
            body["protocol"] != "OIX"
            or body["version"] != SECURE_VERSION
            or body["algorithm"] != "X25519"
            or body["agent_id"] != fingerprint(signing_public_key)
        ):
            return False
        public_raw = _unb64(body["public_key"])
        if len(public_raw) != 32:
            return False
        issued_at = body["issued_at"]
        expires_at = body["expires_at"]
        if (
            not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
        ):
            return False
        current = int(time.time()) if now is None else now
        if issued_at > current + 60 or expires_at < current:
            return False
        if not 1 <= expires_at - issued_at <= MAX_CERTIFICATE_TTL:
            return False
        Ed25519PublicKey.from_public_bytes(signing_public_key).verify(
            _unb64(certificate["signature"]), canonical_json(body)
        )
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, binascii.Error):
        return False


def _derive_key(
    shared_secret: bytes,
    sender: str,
    recipient: str,
    recipient_key_fingerprint: str,
) -> bytes:
    salt = hashlib.sha256(
        canonical_json({
            "sender": sender,
            "recipient": recipient,
            "recipient_key_fingerprint": recipient_key_fingerprint,
        })
    ).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"OIX/secure-envelope/" + SECURE_VERSION.encode("ascii"),
    ).derive(shared_secret)


def encrypt_envelope(
    envelope: dict[str, Any],
    recipient_certificate: dict[str, Any],
    recipient_signing_public_key: bytes,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Encrypt an already-signed OIX message to a certified recipient X25519 key."""
    if not verify_encryption_certificate(
        recipient_certificate, recipient_signing_public_key, now=now
    ):
        raise SecureEnvelopeError("recipient encryption certificate is invalid or expired")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("body"), dict):
        raise SecureEnvelopeError("inner OIX message envelope is malformed")
    body = envelope["body"]
    sender = body.get("sender")
    recipient = body.get("recipient")
    recipient_id = recipient_certificate["body"]["agent_id"]
    if not isinstance(sender, str) or not sender:
        raise SecureEnvelopeError("inner OIX sender is required")
    if recipient != recipient_id:
        raise SecureEnvelopeError("inner OIX recipient does not match encryption certificate")
    plaintext = canonical_json(envelope)
    if len(plaintext) > MAX_MESSAGE_BYTES:
        raise SecureEnvelopeError("inner OIX message exceeds the 1 MB limit")

    recipient_public_raw = _unb64(recipient_certificate["body"]["public_key"])
    recipient_public = X25519PublicKey.from_public_bytes(recipient_public_raw)
    recipient_key_fingerprint = hashlib.sha256(recipient_public_raw).hexdigest()
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_raw = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    nonce = os.urandom(12)
    header = {
        "protocol": "OIX",
        "version": SECURE_VERSION,
        "sender": sender,
        "recipient": recipient_id,
        "recipient_key_fingerprint": recipient_key_fingerprint,
        "ephemeral_public_key": _b64(ephemeral_public_raw),
        "nonce": _b64(nonce),
    }
    key = _derive_key(
        ephemeral_private.exchange(recipient_public),
        sender,
        recipient_id,
        recipient_key_fingerprint,
    )
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, canonical_json(header))
    secure_envelope = {"header": header, "ciphertext": _b64(ciphertext)}
    if len(canonical_json(secure_envelope)) > MAX_SECURE_ENVELOPE_BYTES:
        raise SecureEnvelopeError("encrypted envelope exceeds the 1.1 MB limit")
    return secure_envelope


def decrypt_envelope(
    secure_envelope: dict[str, Any],
    recipient_private_key: X25519PrivateKey,
    recipient_certificate: dict[str, Any],
    recipient_signing_public_key: bytes,
    sender_signing_public_key: bytes,
    local_agent_id: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Decrypt, authenticate, and validate the exact recipient and inner sender."""
    if not verify_encryption_certificate(
        recipient_certificate, recipient_signing_public_key, now=now
    ):
        raise SecureEnvelopeError("local encryption certificate is invalid or expired")
    if not isinstance(secure_envelope, dict) or set(secure_envelope) != {"header", "ciphertext"}:
        raise SecureEnvelopeError("encrypted envelope has an invalid shape")
    header = secure_envelope["header"]
    if not isinstance(header, dict) or set(header) != _HEADER_FIELDS:
        raise SecureEnvelopeError("encrypted envelope header has an invalid shape")
    if header["protocol"] != "OIX" or header["version"] != SECURE_VERSION:
        raise SecureEnvelopeError("unsupported secure envelope protocol version")
    if header["recipient"] != local_agent_id:
        raise SecureEnvelopeError("encrypted envelope is addressed to another agent")
    if header["sender"] != fingerprint(sender_signing_public_key):
        raise SecureEnvelopeError("encrypted envelope sender does not match trusted signing key")

    recipient_public_raw = recipient_private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    certificate_public_raw = _unb64(recipient_certificate["body"]["public_key"])
    if recipient_public_raw != certificate_public_raw:
        raise SecureEnvelopeError("local private key does not match certified encryption key")
    recipient_key_fingerprint = hashlib.sha256(recipient_public_raw).hexdigest()
    if header["recipient_key_fingerprint"] != recipient_key_fingerprint:
        raise SecureEnvelopeError("encrypted envelope targets a different encryption key")

    ephemeral_raw = _unb64(header["ephemeral_public_key"])
    nonce = _unb64(header["nonce"])
    ciphertext = _unb64(secure_envelope["ciphertext"])
    if len(ephemeral_raw) != 32 or len(nonce) != 12:
        raise SecureEnvelopeError("invalid ephemeral key or AEAD nonce length")
    if len(canonical_json(secure_envelope)) > MAX_SECURE_ENVELOPE_BYTES:
        raise SecureEnvelopeError("encrypted envelope exceeds the 1.1 MB limit")
    key = _derive_key(
        recipient_private_key.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw)),
        header["sender"],
        header["recipient"],
        recipient_key_fingerprint,
    )
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            nonce, ciphertext, canonical_json(header)
        )
    except InvalidTag as exc:
        raise SecureEnvelopeError("encrypted envelope authentication failed") from exc
    try:
        inner = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecureEnvelopeError("decrypted message is not valid JSON") from exc
    if not isinstance(inner, dict) or not isinstance(inner.get("body"), dict):
        raise SecureEnvelopeError("decrypted OIX message is malformed")
    if inner["body"].get("sender") != header["sender"]:
        raise SecureEnvelopeError("inner sender does not match encrypted envelope sender")
    if not verify_for_recipient(
        inner, sender_signing_public_key, local_agent_id, now=now
    ):
        raise SecureEnvelopeError("inner OIX signature, recipient, or validity check failed")
    return inner
