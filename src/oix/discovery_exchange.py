"""Bounded, transport-neutral exchange of independently signed OIX discovery records.

This layer packages and ingests records. It does not implement sockets, gossip,
endpoint resolution, peer trust, or task authorization.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

from .canonical import canonical_json
from .discovery import (
    DiscoveryError,
    SQLiteDiscoveryStore,
    _validate_timestamp,
)

MAX_EXCHANGE_RECORDS = 64
MAX_EXCHANGE_BYTES = 512 * 1024
MAX_EXCHANGE_FUTURE_SKEW_SECONDS = 60


class ExchangeError(ValueError):
    """A discovery exchange batch is malformed or exceeds resource limits."""


def _validate_batch_id(value: Any) -> None:
    try:
        valid = isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        raise ExchangeError("batch_id must be a canonical UUID")


def _validate_timestamp_value(value: Any, field: str) -> None:
    try:
        _validate_timestamp(value, field)
    except DiscoveryError as exc:
        raise ExchangeError(str(exc)) from exc


def create_exchange_batch(records: list[dict[str, Any]], *, now: int) -> dict[str, Any]:
    """Package signed announcement/card pairs for forwarding by an untrusted relay."""
    _validate_timestamp_value(now, "now")
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_EXCHANGE_RECORDS:
        raise ExchangeError(f"records must contain 1 to {MAX_EXCHANGE_RECORDS} entries")
    for item in records:
        if not isinstance(item, dict) or set(item) != {"announcement", "card"}:
            raise ExchangeError("each record must contain exactly announcement and card")
    body = {
        "protocol": "OIX-DISCOVERY-EXCHANGE",
        "protocol_version": "0.1",
        "batch_id": str(uuid.uuid4()),
        "created_at": now,
        "records": records,
    }
    try:
        encoded = canonical_json(body)
    except (TypeError, ValueError) as exc:
        raise ExchangeError("batch contains values outside the OIX JSON data model") from exc
    if len(encoded) > MAX_EXCHANGE_BYTES:
        raise ExchangeError(f"batch exceeds {MAX_EXCHANGE_BYTES} byte limit")
    return {"exchange": body}


def inspect_exchange_batch(batch: dict[str, Any], *, now: int) -> tuple[list[dict[str, Any]], str]:
    """Validate batch framing and resource bounds; nested signatures are checked on ingest."""
    _validate_timestamp(now, "now")
    if not isinstance(batch, dict) or set(batch) != {"exchange"}:
        raise ExchangeError("batch must contain exactly one exchange object")
    body = batch["exchange"]
    required = {"protocol", "protocol_version", "batch_id", "created_at", "records"}
    if not isinstance(body, dict) or set(body) != required:
        raise ExchangeError("exchange object has an invalid shape")
    if body["protocol"] != "OIX-DISCOVERY-EXCHANGE" or body["protocol_version"] != "0.1":
        raise ExchangeError("unsupported discovery exchange protocol")
    _validate_batch_id(body["batch_id"])
    _validate_timestamp_value(body["created_at"], "created_at")
    if body["created_at"] > now + MAX_EXCHANGE_FUTURE_SKEW_SECONDS:
        raise ExchangeError("batch creation time is too far in the future")
    records = body["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_EXCHANGE_RECORDS:
        raise ExchangeError(f"records must contain 1 to {MAX_EXCHANGE_RECORDS} entries")
    for item in records:
        if not isinstance(item, dict) or set(item) != {"announcement", "card"}:
            raise ExchangeError("each record must contain exactly announcement and card")
    try:
        encoded = canonical_json(body)
    except (TypeError, ValueError) as exc:
        raise ExchangeError("batch contains values outside the OIX JSON data model") from exc
    if len(encoded) > MAX_EXCHANGE_BYTES:
        raise ExchangeError(f"batch exceeds {MAX_EXCHANGE_BYTES} byte limit")
    digest = hashlib.sha256(encoded).hexdigest()
    return records, digest


def ingest_exchange_batch(
    batch: dict[str, Any], store: SQLiteDiscoveryStore, *, now: int
) -> dict[str, Any]:
    """Independently verify and ingest each record; invalid entries do not poison valid peers."""
    records, digest = inspect_exchange_batch(batch, now=now)
    accepted: list[str] = []
    rejected: list[dict[str, Any]] = []
    for index, item in enumerate(records):
        try:
            agent_id = store.record(item["announcement"], item["card"], now=now)
        except (DiscoveryError, KeyError, TypeError, ValueError) as exc:
            rejected.append({"index": index, "reason": str(exc)})
        else:
            accepted.append(agent_id)
    return {
        "batch_id": batch["exchange"]["batch_id"],
        "batch_sha256": digest,
        "received": len(records),
        "accepted": accepted,
        "rejected": rejected,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "trust_state": "discovered_untrusted",
    }
