"""Approval-gated signing and local persistence for OIX task results.

This module deliberately provides no transport. Signed envelopes remain in the
SQLite outbox until a separately reviewed transport acknowledges delivery.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .envelope import create_message
from .identity import fingerprint


class ResultChannelError(RuntimeError):
    """A result cannot safely move through the outbound approval lifecycle."""


class ResultSchemaError(ResultChannelError):
    """The shared OIX/Open-Swarm database lacks the expected result schema."""


class SQLiteResultPublisher:
    """Operator-controlled OIX task-result publisher over a shared SQLite file.

    Lifecycle: pending_approval -> approved -> signed -> delivered.
    An operator may instead reject a pending result. Signing persists the exact
    envelope before any transport can read it, so retries reuse the same message.
    This class never opens a socket or sends data.
    """

    def __init__(
        self,
        database: str | Path,
        local_agent_id: str,
        private_key: Ed25519PrivateKey,
    ) -> None:
        if not isinstance(local_agent_id, str) or not local_agent_id.strip():
            raise ValueError("local_agent_id must be non-empty")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        public_raw = private_key.public_key().public_bytes_raw()
        if fingerprint(public_raw) != local_agent_id:
            raise ValueError("private key does not belong to local_agent_id")
        self.database = str(database)
        self.local_agent_id = local_agent_id
        self.private_key = private_key
        with self._connect() as db:
            self._require_schema(db)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @staticmethod
    def _require_schema(db: sqlite3.Connection) -> None:
        tables = {
            row["name"]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "oix_result_outbox" not in tables:
            raise ResultSchemaError(
                "shared database is missing oix_result_outbox; initialize the "
                "Open-Swarm OIX handoff adapter first"
            )
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(oix_result_outbox)")
        }
        required = {
            "task_id", "sender", "request_message_id", "terminal_status",
            "payload_json", "status", "created_at", "decided_at",
            "signed_envelope_json", "signed_message_id", "delivered_at",
            "rejection_reason",
        }
        if not required.issubset(columns):
            raise ResultSchemaError("oix_result_outbox schema is incompatible")

    def pending(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT task_id,sender,request_message_id,terminal_status,
                       payload_json,status,created_at
                FROM oix_result_outbox
                WHERE status='pending_approval'
                ORDER BY created_at,task_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "task_id": row["task_id"],
                "sender": row["sender"],
                "request_message_id": row["request_message_id"],
                "terminal_status": row["terminal_status"],
                "payload": json.loads(row["payload_json"]),
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def decide(self, task_id: str, *, approve: bool) -> str:
        if not isinstance(approve, bool):
            raise TypeError("approve must be a boolean")
        now = datetime.now(UTC).isoformat()
        status = "approved" if approve else "rejected"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM oix_result_outbox WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise ResultChannelError("result does not exist")
            if row["status"] != "pending_approval":
                raise ResultChannelError("result is not pending operator approval")
            db.execute(
                """
                UPDATE oix_result_outbox
                SET status=?,decided_at=?,rejection_reason=?
                WHERE task_id=? AND status='pending_approval'
                """,
                (
                    status,
                    now,
                    None if approve else "rejected by operator",
                    task_id,
                ),
            )
        return status

    def sign_approved(self, task_id: str, *, ttl_seconds: int = 300) -> dict[str, Any]:
        """Create once and persist a signed task.result envelope for later delivery."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT sender,payload_json,status,signed_envelope_json
                FROM oix_result_outbox WHERE task_id=?
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                raise ResultChannelError("result does not exist")
            if row["status"] in {"signed", "delivered"}:
                if not row["signed_envelope_json"]:
                    raise ResultChannelError("signed result is missing its persisted envelope")
                return json.loads(row["signed_envelope_json"])
            if row["status"] != "approved":
                raise ResultChannelError("result must be operator-approved before signing")
            payload = json.loads(row["payload_json"])
            envelope = create_message(
                self.private_key,
                row["sender"],
                "task.result",
                payload,
                ttl_seconds=ttl_seconds,
            )
            encoded = json.dumps(
                envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            changed = db.execute(
                """
                UPDATE oix_result_outbox
                SET status='signed',signed_envelope_json=?,signed_message_id=?
                WHERE task_id=? AND status='approved'
                """,
                (encoded, envelope["body"]["message_id"], task_id),
            ).rowcount
            if changed != 1:
                raise ResultChannelError("result approval changed during signing")
            return envelope

    def pending_delivery(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT task_id,sender,request_message_id,signed_message_id,
                       signed_envelope_json,created_at
                FROM oix_result_outbox
                WHERE status='signed'
                ORDER BY created_at,task_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "task_id": row["task_id"],
                "sender": row["sender"],
                "request_message_id": row["request_message_id"],
                "message_id": row["signed_message_id"],
                "envelope": json.loads(row["signed_envelope_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def mark_delivered(self, task_id: str, message_id: str) -> bool:
        """Record transport acknowledgement for the exact persisted envelope."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT status,signed_message_id
                FROM oix_result_outbox WHERE task_id=?
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                raise ResultChannelError("result does not exist")
            if row["status"] == "delivered":
                if row["signed_message_id"] != message_id:
                    raise ResultChannelError("delivery acknowledgement message ID mismatch")
                return False
            if row["status"] != "signed":
                raise ResultChannelError("only a signed result can be marked delivered")
            if row["signed_message_id"] != message_id:
                raise ResultChannelError("delivery acknowledgement message ID mismatch")
            db.execute(
                """
                UPDATE oix_result_outbox
                SET status='delivered',delivered_at=?
                WHERE task_id=? AND status='signed'
                """,
                (datetime.now(UTC).isoformat(), task_id),
            )
        return True
