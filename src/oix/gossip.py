"""Bounded local gossip planning for verified OIX discovery batches.

This module computes forwarding decisions for an operator-approved peer set.
It does not open sockets, perform peer discovery, or claim that a planned
forward was delivered. Hop counts are advisory metadata, not a security boundary.
"""
from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .discovery import verify_announcement
from .discovery_exchange import (
    ExchangeError,
    inspect_exchange_batch,
)

MAX_GOSSIP_HOPS = 8
MAX_GOSSIP_FANOUT = 8
MAX_GOSSIP_CANDIDATES = 256
MAX_PEER_FORWARDS_PER_HOUR = 60
DEFAULT_DEDUPE_TTL_SECONDS = 3600
_AGENT_ID = re.compile(r"^ed25519:[0-9a-f]{64}$")


class GossipError(ValueError):
    """A gossip request is invalid or exceeds local forwarding policy."""


@dataclass(frozen=True)
class GossipPolicy:
    max_hops: int = 4
    max_fanout: int = 3
    max_candidates: int = MAX_GOSSIP_CANDIDATES
    per_peer_hourly_limit: int = 30
    dedupe_ttl_seconds: int = DEFAULT_DEDUPE_TTL_SECONDS

    def __post_init__(self) -> None:
        limits = (
            ("max_hops", self.max_hops, 1, MAX_GOSSIP_HOPS),
            ("max_fanout", self.max_fanout, 1, MAX_GOSSIP_FANOUT),
            ("max_candidates", self.max_candidates, 1, MAX_GOSSIP_CANDIDATES),
            ("per_peer_hourly_limit", self.per_peer_hourly_limit, 1,
             MAX_PEER_FORWARDS_PER_HOUR),
            ("dedupe_ttl_seconds", self.dedupe_ttl_seconds, 1, 86400),
        )
        for name, value, minimum, maximum in limits:
            if (not isinstance(value, int) or isinstance(value, bool)
                    or not minimum <= value <= maximum):
                raise GossipError(f"{name} must be between {minimum} and {maximum}")


class GossipLedger:
    """Durable local deduplication and per-peer forwarding quota ledger."""

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        path = Path(self.database)
        if path.is_symlink() or path.parent.is_symlink():
            raise GossipError("gossip database path must not traverse a symlink")
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
                """CREATE TABLE IF NOT EXISTS gossip_seen (
                    batch_sha256 TEXT PRIMARY KEY,
                    first_seen_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )"""
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS gossip_forward_plan (
                    batch_sha256 TEXT NOT NULL,
                    peer_id TEXT NOT NULL,
                    planned_at INTEGER NOT NULL,
                    window_start INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('planned','sent','cancelled')),
                    PRIMARY KEY(batch_sha256, peer_id)
                )"""
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS gossip_peer_quota (
                    peer_id TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    forwards INTEGER NOT NULL CHECK(forwards >= 0),
                    PRIMARY KEY(peer_id, window_start)
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def reserve(
        self,
        batch_sha256: str,
        peer_ids: list[str],
        *,
        now: int,
        ttl_seconds: int,
        max_fanout: int,
        per_peer_hourly_limit: int,
    ) -> tuple[bool, list[str], dict[str, str]]:
        """Atomically deduplicate a batch and reserve quota for approved targets."""
        if not re.fullmatch(r"[0-9a-f]{64}", batch_sha256):
            raise GossipError("batch digest must be a lowercase SHA-256 hex value")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise GossipError("now must be a non-negative integer timestamp")
        if not isinstance(peer_ids, list):
            raise GossipError("peer identifiers must be supplied as a list")
        if any(not isinstance(peer, str) or not _AGENT_ID.fullmatch(peer) for peer in peer_ids):
            raise GossipError("peer identifiers must be Ed25519 fingerprints")
        unique = sorted(set(peer_ids))
        if (not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool)
                or not 1 <= ttl_seconds <= 86400):
            raise GossipError("ttl_seconds must be between 1 and 86400")
        if (not isinstance(max_fanout, int) or isinstance(max_fanout, bool)
                or not 1 <= max_fanout <= MAX_GOSSIP_FANOUT):
            raise GossipError("max_fanout is outside supported limits")
        if (not isinstance(per_peer_hourly_limit, int)
                or isinstance(per_peer_hourly_limit, bool)
                or not 1 <= per_peer_hourly_limit <= MAX_PEER_FORWARDS_PER_HOUR):
            raise GossipError("per_peer_hourly_limit is outside supported limits")
        window_start = now - (now % 3600)
        selected: list[str] = []
        blocked: dict[str, str] = {}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM gossip_seen WHERE expires_at<=?", (now,))
            seen = db.execute(
                "SELECT 1 FROM gossip_seen WHERE batch_sha256=?", (batch_sha256,)
            ).fetchone()
            if seen:
                db.commit()
                return False, [], {"batch": "duplicate"}
            db.execute(
                "INSERT INTO gossip_seen(batch_sha256,first_seen_at,expires_at) VALUES(?,?,?)",
                (batch_sha256, now, now + ttl_seconds),
            )
            for peer_id in unique:
                existing = db.execute(
                    """SELECT state FROM gossip_forward_plan
                       WHERE batch_sha256=? AND peer_id=?""",
                    (batch_sha256, peer_id),
                ).fetchone()
                if existing:
                    blocked[peer_id] = "already_planned"
                    continue
                quota = db.execute(
                    """SELECT forwards FROM gossip_peer_quota
                       WHERE peer_id=? AND window_start=?""",
                    (peer_id, window_start),
                ).fetchone()
                used = quota[0] if quota else 0
                if used >= per_peer_hourly_limit:
                    blocked[peer_id] = "hourly_quota"
                    continue
                if len(selected) >= max_fanout:
                    blocked[peer_id] = "fanout_limit"
                    continue
                db.execute(
                    """INSERT INTO gossip_forward_plan(
                        batch_sha256,peer_id,planned_at,window_start,state
                    ) VALUES(?,?,?,?,'planned')""",
                    (batch_sha256, peer_id, now, window_start),
                )
                db.execute(
                    """INSERT INTO gossip_peer_quota(peer_id,window_start,forwards)
                       VALUES(?,?,1)
                       ON CONFLICT(peer_id,window_start) DO UPDATE
                       SET forwards=forwards+1""",
                    (peer_id, window_start),
                )
                selected.append(peer_id)
            db.commit()
        return True, selected, blocked

    def mark_sent(self, batch_sha256: str, peer_id: str) -> None:
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE gossip_forward_plan SET state='sent'
                   WHERE batch_sha256=? AND peer_id=? AND state='planned'""",
                (batch_sha256, peer_id),
            )
            if cursor.rowcount != 1:
                raise GossipError("no pending forwarding reservation exists")

    def cancel(self, batch_sha256: str, peer_id: str) -> None:
        """Cancel an unsent reservation and return its quota within the original hour."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT window_start FROM gossip_forward_plan
                   WHERE batch_sha256=? AND peer_id=? AND state='planned'""",
                (batch_sha256, peer_id),
            ).fetchone()
            if row is None:
                raise GossipError("no pending forwarding reservation exists")
            db.execute(
                """UPDATE gossip_forward_plan SET state='cancelled'
                   WHERE batch_sha256=? AND peer_id=?""",
                (batch_sha256, peer_id),
            )
            db.execute(
                """UPDATE gossip_peer_quota SET forwards=MAX(0,forwards-1)
                   WHERE peer_id=? AND window_start=?""",
                (peer_id, row[0]),
            )
            db.commit()


def plan_gossip_forwarding(
    batch: dict[str, Any],
    ledger: GossipLedger,
    *,
    inbound_peer_id: str | None,
    operator_approved_peer_ids: list[str],
    hop_count: int,
    now: int,
    policy: GossipPolicy | None = None,
) -> dict[str, Any]:
    """Verify a batch and reserve bounded forwarding to explicitly approved peers."""
    policy = policy or GossipPolicy()
    if not isinstance(hop_count, int) or isinstance(hop_count, bool) or hop_count < 0:
        raise GossipError("hop_count must be a non-negative integer")
    try:
        records, digest = inspect_exchange_batch(batch, now=now)
    except ExchangeError as exc:
        raise GossipError(str(exc)) from exc
    if hop_count >= policy.max_hops:
        return {"status": "hop_limit", "forwarded_batch": None, "destinations": []}
    if not isinstance(operator_approved_peer_ids, list):
        raise GossipError("operator-approved peers must be supplied as a list")
    if len(operator_approved_peer_ids) > policy.max_candidates:
        raise GossipError("approved peer candidate list exceeds configured limit")
    if (inbound_peer_id is not None
            and (not isinstance(inbound_peer_id, str)
                 or not _AGENT_ID.fullmatch(inbound_peer_id))):
        raise GossipError("inbound peer identifier is malformed")
    for index, item in enumerate(records):
        if not verify_announcement(item["announcement"], item["card"], now=now):
            raise GossipError(f"discovery record {index} failed signature or expiry verification")
    if not records:
        raise GossipError("no verified records available for forwarding")
    # Preserve the original batch identifier and digest across relay hops.
    # Repackaging would generate a fresh UUID and defeat duplicate suppression.
    candidates = [
        peer for peer in operator_approved_peer_ids
        if peer != inbound_peer_id
    ]
    if not candidates:
        return {
            "status": "no_eligible_peers",
            "batch_sha256": digest,
            "forwarded_batch": None,
            "destinations": [],
            "blocked": {},
            "hop_count": hop_count,
            "trust_state": "discovered_untrusted",
        }
    is_new, destinations, blocked = ledger.reserve(
        digest,
        candidates,
        now=now,
        ttl_seconds=policy.dedupe_ttl_seconds,
        max_fanout=policy.max_fanout,
        per_peer_hourly_limit=policy.per_peer_hourly_limit,
    )
    if not is_new:
        return {
            "status": "duplicate",
            "batch_sha256": digest,
            "forwarded_batch": None,
            "destinations": [],
            "blocked": blocked,
            "hop_count": hop_count,
        }
    return {
        "status": "planned" if destinations else "no_eligible_peers",
        "batch_sha256": digest,
        "forwarded_batch": batch if destinations else None,
        "destinations": destinations,
        "blocked": blocked,
        "hop_count": hop_count + 1,
        "trust_state": "discovered_untrusted",
    }
