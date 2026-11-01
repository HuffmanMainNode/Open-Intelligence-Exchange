"""Ed25519 agent identity and signed agent cards."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json

SCHEME = "ed25519"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def fingerprint(public_key: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_key).hexdigest()


def generate_identity(directory: str | Path, display_name: str, capabilities: list[str]) -> dict[str, Any]:
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    private_path = path / "private.key"
    card_path = path / "agent-card.json"
    if private_path.exists() or card_path.exists():
        raise FileExistsError("identity files already exist; refusing to overwrite keys")
    with private_path.open("xb") as key_file:
        key_file.write(private_raw)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    card = {
        "protocol": "OIX",
        "protocol_version": "0.1",
        "agent_id": fingerprint(public_raw),
        "display_name": display_name,
        "public_key": _b64(public_raw),
        "key_algorithm": SCHEME,
        "capabilities": sorted(set(capabilities)),
    }
    signature = private.sign(canonical_json(card))
    signed = {"card": card, "signature": _b64(signature)}
    with card_path.open("x", encoding="utf-8") as card_file:
        card_file.write(json.dumps(signed, indent=2, ensure_ascii=False) + "\n")
    return signed


def load_private_key(directory: str | Path) -> Ed25519PrivateKey:
    raw = (Path(directory) / "private.key").read_bytes()
    if len(raw) != 32:
        raise ValueError("invalid Ed25519 private key length")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_card(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_card(signed_card: dict[str, Any]) -> bool:
    try:
        card = signed_card["card"]
        public_raw = _unb64(card["public_key"])
        if len(public_raw) != 32 or fingerprint(public_raw) != card["agent_id"]:
            return False
        if card.get("protocol") != "OIX" or card.get("protocol_version") != "0.1":
            return False
        if card.get("key_algorithm") != SCHEME or not isinstance(card.get("capabilities"), list):
            return False
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            _unb64(signed_card["signature"]), canonical_json(card)
        )
        return True
    except Exception:
        return False
