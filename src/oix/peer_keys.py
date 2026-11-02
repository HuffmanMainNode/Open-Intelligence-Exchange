"""Operator-controlled peer encryption-key lifecycle registry."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .identity import fingerprint
from .secure_transport import (
    encrypt_envelope,
    encryption_key_fingerprint,
    verify_encryption_certificate,
)


class PeerKeyError(ValueError):
    """A peer encryption-key lifecycle transition is invalid."""


class SQLitePeerKeyStore:
    """Store certified peer keys with monotonic, explicit rotation approval.

    A certificate proves possession/binding to a trusted signing identity. It
    does not automatically authorize replacing a key already in use.
    """

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        path = Path(self.database)
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError("peer key database path must not traverse a symlink")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            try:
                descriptor = os.open(
                    self.database, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
                )
            except FileExistsError:
                os.chmod(path, 0o600)
            else:
                os.close(descriptor)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS peer_encryption_keys (
                    agent_id TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    certificate_json TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','superseded','revoked')),
                    installed_at INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY(agent_id,key_fingerprint)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_active_key
                    ON peer_encryption_keys(agent_id) WHERE status='active';
                CREATE TABLE IF NOT EXISTS peer_key_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    event TEXT NOT NULL,
                    occurred_at INTEGER NOT NULL,
                    detail TEXT NOT NULL
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def install(
        self,
        certificate: dict[str, Any],
        trusted_signing_public_key: bytes,
        *,
        approve_rotation: bool = False,
        now: int | None = None,
    ) -> str:
        if not verify_encryption_certificate(
            certificate, trusted_signing_public_key, now=now
        ):
            raise PeerKeyError("peer encryption certificate is invalid or expired")
        body = certificate["body"]
        agent_id = body["agent_id"]
        key_fp = encryption_key_fingerprint(certificate)
        encoded = canonical_json(certificate).decode("utf-8")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute(
                "SELECT key_fingerprint,issued_at FROM peer_encryption_keys "
                "WHERE agent_id=? AND status='active'", (agent_id,)
            ).fetchone()
            if active and active["key_fingerprint"] == key_fp:
                db.commit()
                return key_fp
            if active:
                if not approve_rotation:
                    raise PeerKeyError("key rotation requires explicit operator approval")
                if body["issued_at"] <= active["issued_at"]:
                    raise PeerKeyError("replacement key certificate must be newer than active key")
                db.execute(
                    "UPDATE peer_encryption_keys SET status='superseded' "
                    "WHERE agent_id=? AND status IN ('active','superseded')", (agent_id,)
                )
            existing = db.execute(
                "SELECT status FROM peer_encryption_keys WHERE agent_id=? AND key_fingerprint=?",
                (agent_id, key_fp),
            ).fetchone()
            if existing and existing["status"] != "active":
                raise PeerKeyError("superseded or revoked encryption key cannot be reactivated")
            db.execute(
                """INSERT INTO peer_encryption_keys(
                    agent_id,key_fingerprint,certificate_json,issued_at,expires_at,status
                ) VALUES(?,?,?,?,?,'active')
                ON CONFLICT(agent_id,key_fingerprint) DO UPDATE SET
                    certificate_json=excluded.certificate_json,
                    issued_at=excluded.issued_at,expires_at=excluded.expires_at,status='active'""",
                (agent_id, key_fp, encoded, body["issued_at"], body["expires_at"]),
            )
            db.execute(
                "INSERT INTO peer_key_events(agent_id,key_fingerprint,event,occurred_at,detail) "
                "VALUES(?,?,?,?,'operator-approved certificate installation')",
                (agent_id, key_fp, "installed" if not active else "rotated",
                 int(now if now is not None else body["issued_at"])),
            )
            db.commit()
        return key_fp

    def revoke(self, agent_id: str, *, now: int, reason: str) -> bool:
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise ValueError("now must be a non-negative integer timestamp")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 256:
            raise ValueError("reason must contain 1 to 256 characters")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT key_fingerprint FROM peer_encryption_keys "
                "WHERE agent_id=? AND status IN ('active','superseded')", (agent_id,)
            ).fetchall()
            if not rows:
                db.commit()
                return False
            db.execute(
                "UPDATE peer_encryption_keys SET status='revoked' "
                "WHERE agent_id=? AND status IN ('active','superseded')", (agent_id,)
            )
            for row in rows:
                db.execute(
                    "INSERT INTO peer_key_events(agent_id,key_fingerprint,event,occurred_at,detail) "
                    "VALUES(?,?, 'revoked', ?, ?)",
                    (agent_id, row["key_fingerprint"], now, reason.strip()),
                )
            db.commit()
        return True

    def active(self, agent_id: str, *, now: int) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT certificate_json,expires_at FROM peer_encryption_keys "
                "WHERE agent_id=? AND status='active'", (agent_id,)
            ).fetchone()
        if row is None or row["expires_at"] < now:
            return None
        return json.loads(row["certificate_json"])

    def encrypt_for_peer(
        self,
        envelope: dict[str, Any],
        trusted_signing_public_key: bytes,
        *,
        now: int,
    ) -> dict[str, Any]:
        """Encrypt only to the currently installed, non-expired peer key."""
        body = envelope.get("body", {}) if isinstance(envelope, dict) else {}
        recipient = body.get("recipient")
        if not isinstance(recipient, str) or recipient != fingerprint(trusted_signing_public_key):
            raise PeerKeyError("message recipient does not match trusted peer identity")
        certificate = self.active(recipient, now=now)
        if certificate is None:
            raise PeerKeyError("peer has no active, non-expired encryption certificate")
        return encrypt_envelope(
            envelope, certificate, trusted_signing_public_key, now=now
        )

    def history(self, agent_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT key_fingerprint,event,occurred_at,detail FROM peer_key_events "
                "WHERE agent_id=? ORDER BY event_id", (agent_id,)
            ).fetchall()
        return [dict(row) for row in rows]
