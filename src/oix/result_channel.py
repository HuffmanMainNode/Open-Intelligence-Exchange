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

from .envelope import create_message, verify_message
from .identity import fingerprint
from .prekeys import encrypt_prekey_envelope, verify_prekey_bundle
from .receipts import message_digest, verify_delivery_receipt
from .secure_transport import (
    MAX_SECURE_ENVELOPE_BYTES,
    encrypt_envelope,
    encryption_key_fingerprint,
    verify_encryption_certificate,
)


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
            columns = {
                row["name"] for row in db.execute("PRAGMA table_info(oix_result_outbox)")
            }
            migrations = {
                "secure_envelope_json": "TEXT",
                "secure_key_fingerprint": "TEXT",
                "secure_created_at": "TEXT",
                "receipt_envelope_json": "TEXT",
                "receipt_message_id": "TEXT",
                "receipt_content_digest": "TEXT",
                "secure_mode": "TEXT",
            }
            for column, declaration in migrations.items():
                if column not in columns:
                    db.execute(
                        f"ALTER TABLE oix_result_outbox ADD COLUMN {column} {declaration}"
                    )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _decode_persisted_envelope(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            envelope = json.loads(row["signed_envelope_json"])
        except (TypeError, ValueError) as exc:
            raise ResultChannelError("persisted signed envelope is not valid JSON") from exc
        public_key = self.private_key.public_key().public_bytes_raw()
        body = envelope.get("body", {}) if isinstance(envelope, dict) else {}
        if (
            not verify_message(envelope, public_key)
            or body.get("sender") != self.local_agent_id
            or body.get("recipient") != row["sender"]
            or body.get("type") != "task.result"
            or body.get("message_id") != row["signed_message_id"]
        ):
            raise ResultChannelError("persisted signed envelope failed integrity checks")
        return envelope

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
                SELECT sender,payload_json,status,signed_envelope_json,signed_message_id
                FROM oix_result_outbox WHERE task_id=?
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                raise ResultChannelError("result does not exist")
            if row["status"] in {"signed", "delivered"}:
                if not row["signed_envelope_json"]:
                    raise ResultChannelError("signed result is missing its persisted envelope")
                return self._decode_persisted_envelope(row)
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

    def encrypt_approved(
        self,
        task_id: str,
        recipient_certificate: dict[str, Any],
        recipient_signing_public_key: bytes,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Encrypt and persist the approved signed result for its original peer.

        The certificate must be verified against the original peer's trusted
        Ed25519 key. Repeated calls with the same key reuse the exact wrapper.
        """
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT sender,status,signed_envelope_json,signed_message_id,
                       secure_envelope_json,secure_key_fingerprint,secure_mode
                FROM oix_result_outbox WHERE task_id=?
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                raise ResultChannelError("result does not exist")
            if row["status"] != "signed":
                raise ResultChannelError("result must be signed before encryption")
            if (
                not verify_encryption_certificate(
                    recipient_certificate, recipient_signing_public_key, now=now
                )
                or fingerprint(recipient_signing_public_key) != row["sender"]
                or recipient_certificate["body"]["agent_id"] != row["sender"]
            ):
                raise ResultChannelError(
                    "recipient encryption certificate does not match the original trusted peer"
                )
            key_fingerprint = encryption_key_fingerprint(recipient_certificate)
            if (
                row["secure_envelope_json"]
                and row["secure_key_fingerprint"] == key_fingerprint
                and row["secure_mode"] in {None, "static_x25519"}
            ):
                return self._decode_persisted_secure_envelope(
                    row["secure_envelope_json"], row["sender"], key_fingerprint,
                    mode="static_x25519",
                )
            signed = self._decode_persisted_envelope(row)
            secure = encrypt_envelope(
                signed, recipient_certificate, recipient_signing_public_key, now=now
            )
            encoded = json.dumps(
                secure, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            if len(encoded.encode("utf-8")) > MAX_SECURE_ENVELOPE_BYTES:
                raise ResultChannelError("encrypted result exceeds the secure envelope limit")
            db.execute(
                """
                UPDATE oix_result_outbox
                SET secure_envelope_json=?,secure_key_fingerprint=?,secure_created_at=?,
                    secure_mode='static_x25519'
                WHERE task_id=? AND status='signed' AND signed_message_id=?
                """,
                (
                    encoded,
                    key_fingerprint,
                    datetime.now(UTC).isoformat(),
                    task_id,
                    row["signed_message_id"],
                ),
            )
            return secure

    def encrypt_approved_with_prekey(
        self,
        task_id: str,
        recipient_bundle: dict[str, Any],
        recipient_signing_public_key: bytes,
        *,
        key_id: str | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Persist a result encrypted to one certified, single-use peer prekey."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT sender,status,signed_envelope_json,signed_message_id,
                       secure_envelope_json,secure_key_fingerprint,secure_mode
                FROM oix_result_outbox WHERE task_id=?
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                raise ResultChannelError("result does not exist")
            if row["status"] != "signed":
                raise ResultChannelError("result must be signed before encryption")
            if (
                fingerprint(recipient_signing_public_key) != row["sender"]
                or not verify_prekey_bundle(
                    recipient_bundle, recipient_signing_public_key, now=now
                )
                or recipient_bundle["body"]["agent_id"] != row["sender"]
            ):
                raise ResultChannelError(
                    "recipient prekey bundle does not match the original trusted peer"
                )
            if row["secure_envelope_json"] and row["secure_mode"] == "one_time_prekey":
                existing = json.loads(row["secure_envelope_json"])
                existing_header = existing.get("header", {}) if isinstance(existing, dict) else {}
                available_ids = {
                    item["key_id"] for item in recipient_bundle["body"]["keys"]
                }
                existing_id = existing_header.get("prekey_id")
                if (
                    existing_id in available_ids
                    and (key_id is None or key_id == existing_id)
                ):
                    return self._decode_persisted_secure_envelope(
                        row["secure_envelope_json"],
                        row["sender"],
                        row["secure_key_fingerprint"],
                        mode="one_time_prekey",
                    )
            signed = self._decode_persisted_envelope(row)
            secure = encrypt_prekey_envelope(
                signed, recipient_bundle, recipient_signing_public_key,
                key_id=key_id, now=now,
            )
            prekey_fingerprint = secure["header"]["prekey_fingerprint"]
            encoded = json.dumps(
                secure, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            if len(encoded.encode("utf-8")) > MAX_SECURE_ENVELOPE_BYTES:
                raise ResultChannelError("encrypted result exceeds the secure envelope limit")
            db.execute(
                """
                UPDATE oix_result_outbox
                SET secure_envelope_json=?,secure_key_fingerprint=?,secure_created_at=?,
                    secure_mode='one_time_prekey'
                WHERE task_id=? AND status='signed' AND signed_message_id=?
                """,
                (
                    encoded, prekey_fingerprint, datetime.now(UTC).isoformat(),
                    task_id, row["signed_message_id"],
                ),
            )
            return secure

    def _decode_persisted_secure_envelope(
        self,
        encoded: str,
        recipient: str,
        key_fingerprint: str | None,
        *,
        mode: str | None = None,
    ) -> dict[str, Any]:
        try:
            secure = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise ResultChannelError("persisted encrypted envelope is not valid JSON") from exc
        header = secure.get("header", {}) if isinstance(secure, dict) else {}
        selected_mode = mode or (
            "one_time_prekey"
            if isinstance(header, dict) and header.get("mode") == "one_time_prekey"
            else "static_x25519"
        )
        key_binding_valid = (
            header.get("prekey_fingerprint") == key_fingerprint
            if selected_mode == "one_time_prekey"
            else header.get("recipient_key_fingerprint") == key_fingerprint
        )
        if (
            not isinstance(secure, dict)
            or set(secure) != {"header", "ciphertext"}
            or not isinstance(header, dict)
            or header.get("protocol") != "OIX"
            or header.get("version") != "1.0"
            or header.get("sender") != self.local_agent_id
            or header.get("recipient") != recipient
            or selected_mode not in {"static_x25519", "one_time_prekey"}
            or not key_binding_valid
            or (
                selected_mode == "one_time_prekey"
                and header.get("mode") != "one_time_prekey"
            )
            or not isinstance(secure.get("ciphertext"), str)
            or len(encoded.encode("utf-8")) > MAX_SECURE_ENVELOPE_BYTES
        ):
            raise ResultChannelError("persisted encrypted envelope failed integrity checks")
        return secure

    def pending_secure_delivery(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Return only persisted encrypted wrappers ready for a future transport."""
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT task_id,sender,request_message_id,signed_message_id,
                       secure_envelope_json,secure_key_fingerprint,secure_mode,created_at
                FROM oix_result_outbox
                WHERE status='signed' AND secure_envelope_json IS NOT NULL
                ORDER BY created_at,task_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "task_id": row["task_id"],
                "recipient": row["sender"],
                "request_message_id": row["request_message_id"],
                "message_id": row["signed_message_id"],
                "envelope": self._decode_persisted_secure_envelope(
                    row["secure_envelope_json"],
                    row["sender"],
                    row["secure_key_fingerprint"],
                    mode=row["secure_mode"],
                ),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def pending_delivery(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Return plaintext signed messages for local inspection only, not network transport."""
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
                "envelope": self._decode_persisted_envelope(row),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def mark_delivered(
        self,
        task_id: str,
        receipt_envelope: dict[str, Any],
        peer_signing_public_key: bytes,
    ) -> bool:
        """Finalize delivery only after a signed, content-bound peer receipt."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT sender,status,signed_message_id,secure_envelope_json,
                       secure_key_fingerprint,secure_mode,receipt_message_id
                FROM oix_result_outbox WHERE task_id=?
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                raise ResultChannelError("result does not exist")
            if row["status"] not in {"signed", "delivered"}:
                raise ResultChannelError("only a signed result can be marked delivered")
            if not row["secure_envelope_json"]:
                raise ResultChannelError("result must be encrypted before delivery")
            secure = self._decode_persisted_secure_envelope(
                row["secure_envelope_json"], row["sender"], row["secure_key_fingerprint"],
                mode=row["secure_mode"],
            )
            digest = message_digest(secure)
            if not verify_delivery_receipt(
                receipt_envelope,
                peer_signing_public_key,
                expected_recipient_agent_id=row["sender"],
                expected_sender_agent_id=self.local_agent_id,
                expected_message_id=row["signed_message_id"],
                expected_content_digest=digest,
            ):
                raise ResultChannelError("delivery receipt signature or message binding is invalid")
            receipt_id = receipt_envelope["body"]["message_id"]
            if row["status"] == "delivered":
                if row["receipt_message_id"] != receipt_id:
                    raise ResultChannelError("a different receipt already finalized delivery")
                return False
            encoded_receipt = json.dumps(
                receipt_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            db.execute(
                """
                UPDATE oix_result_outbox
                SET status='delivered',delivered_at=?,receipt_envelope_json=?,
                    receipt_message_id=?,receipt_content_digest=?
                WHERE task_id=? AND status='signed'
                """,
                (
                    datetime.now(UTC).isoformat(),
                    encoded_receipt,
                    receipt_id,
                    digest,
                    task_id,
                ),
            )
        return True
