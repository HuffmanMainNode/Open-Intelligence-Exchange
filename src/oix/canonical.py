"""Deterministic JSON encoding for the OIX v0.1 restricted data model.

This is intentionally a restricted subset, not a complete RFC 8785 implementation.
Floats and non-string mapping keys are rejected to avoid ambiguous encodings.
"""
from __future__ import annotations

import base64
import binascii
import json
import unicodedata
from typing import Any


def _normalize(value: Any, depth: int = 0) -> Any:
    if depth > 32:
        raise ValueError("maximum JSON nesting depth exceeded")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise TypeError("floating-point values are not allowed in OIX canonical JSON")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        if len(value) > 10_000:
            raise ValueError("array exceeds item limit")
        return [_normalize(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 10_000:
            raise ValueError("object exceeds member limit")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            key = unicodedata.normalize("NFC", key)
            if key in normalized:
                raise ValueError("duplicate key after Unicode normalization")
            normalized[key] = _normalize(item, depth + 1)
        return normalized
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def decode_base64url(value: Any) -> bytes:
    """Decode canonical, unpadded base64url and reject ignored or noncanonical bytes."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not isinstance(value, str) or not value or len(value) % 4 == 1:
        raise ValueError("base64url value must be a non-empty canonical string")
    if any(character not in alphabet for character in value):
        raise ValueError("base64url value contains a non-alphabet character")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base64url value is malformed") from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("base64url value is not canonically encoded")
    return decoded


def canonical_json(value: Any) -> bytes:
    """Return stable UTF-8 JSON bytes for the OIX restricted data model."""
    normalized = _normalize(value)
    return json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
