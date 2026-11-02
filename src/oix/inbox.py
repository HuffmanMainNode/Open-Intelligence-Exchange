"""Trusted-peer receive path with durable, approval-gated local inbox storage.

OIX core persists received data only. It never executes a message payload.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonical_json
from .envelope import ALLOWED_TYPES, MAX_MESSAGE_BYTES, verify_for_recipient
from .identity import _unb64, verify_card
from .policy import CapabilityPolicy

_BODY_FIELDS = {
    "protocol", "version", "message_id", "sender", "recipient", "type",
    "issued_at", "expires_at", "nonce", "requested_capability", "payload",
}


class InboxError(ValueError):
    """A received envelope failed local validation or trust policy."""


class UntrustedPeerError(InboxError):
    """The sender has not been explicitly trusted by this receiver."""


class ReplayError(InboxError):
    """The message ID or nonce has already been used."""


class InboxConflictError(InboxError):
    """A sender reused a message ID for different content."""


class WorkStateError(InboxError):
    """An operator attempted an invalid inbound-work state transition."""


@dataclass(frozen=True, slots=True)
class InboxReceipt:
    sender: str
    message_id: str
    message_type: str
    duplicate: bool
    work_id: str | None
    work_status: str | None


def _validate_rfc3339(value: Any, field: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or not value or len(value) > 64:
        raise InboxError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
    except ValueError as exc:
        raise InboxError(f"{field} must be an RFC 3339 timestamp with timezone") from exc


def _validate_evidence_submit_payload(payload: dict[str, Any]) -> None:
    """Validate the strict, metadata-only evidence.submit 1.0 payload contract."""
    fields = {
        "schema_version", "evidence_id", "evidence_type", "source_uri",
        "source_timestamp", "collected_at", "collector", "method", "artifact",
        "classification", "status", "summary", "limitations",
    }
    if set(payload) != fields:
        raise InboxError("evidence.submit payload fields do not match schema 1.0")
    if payload.get("schema_version") != "1.0":
        raise InboxError("unsupported evidence.submit schema version")
    evidence_id = payload.get("evidence_id")
    try:
        if not isinstance(evidence_id, str) or str(uuid.UUID(evidence_id)) != evidence_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise InboxError("evidence_id must be a canonical lowercase UUID") from exc
    if payload.get("evidence_type") not in {
        "file_manifest", "domain_observation", "transaction_analysis",
        "evm_transaction_inspection", "sbom_analysis",
    }:
        raise InboxError("unsupported evidence_type")
    source_uri = payload.get("source_uri")
    if source_uri is not None:
        if not isinstance(source_uri, str) or len(source_uri) > 2048:
            raise InboxError("source_uri must be null or a bounded HTTPS URL")
        try:
            parsed = urlsplit(source_uri)
            hostname = parsed.hostname
            parsed.port
        except ValueError as exc:
            raise InboxError("source_uri is malformed") from exc
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or any(char.isspace() for char in source_uri)
        ):
            raise InboxError("source_uri must be an HTTPS URL without embedded credentials")
    _validate_rfc3339(payload.get("source_timestamp"), "source_timestamp", nullable=True)
    _validate_rfc3339(payload.get("collected_at"), "collected_at")

    for field in ("collector", "method"):
        value = payload.get(field)
        if (
            not isinstance(value, dict)
            or set(value) != {"name", "version"}
            or not isinstance(value.get("name"), str)
            or not 1 <= len(value["name"].strip()) <= 128
            or not isinstance(value.get("version"), str)
            or not 1 <= len(value["version"].strip()) <= 32
        ):
            raise InboxError(f"{field} must contain bounded name and version fields")

    artifact = payload.get("artifact")
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"sha256", "size_bytes", "media_type"}
        or not isinstance(artifact.get("sha256"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"])
        or not isinstance(artifact.get("size_bytes"), int)
        or isinstance(artifact["size_bytes"], bool)
        or not 0 <= artifact["size_bytes"] <= 1_000_000_000_000
        or not isinstance(artifact.get("media_type"), str)
        or "/" not in artifact["media_type"]
        or any(char.isspace() for char in artifact["media_type"])
        or len(artifact["media_type"]) > 128
    ):
        raise InboxError("artifact must contain a SHA-256, bounded size, and media type")

    if payload.get("classification") not in {"public", "internal", "restricted"}:
        raise InboxError("classification must be public, internal, or restricted")
    if payload.get("status") not in {"observed", "derived", "unverified"}:
        raise InboxError("evidence status is invalid")
    summary = payload.get("summary")
    if not isinstance(summary, dict) or not 1 <= len(summary) <= 64:
        raise InboxError("summary must be an object with 1 to 64 properties")
    try:
        if len(canonical_json(summary)) > 32_768:
            raise InboxError("summary exceeds 32768 bytes")
    except (TypeError, ValueError, RecursionError) as exc:
        raise InboxError("summary must contain deterministic JSON values") from exc
    limitations = payload.get("limitations")
    if (
        not isinstance(limitations, list)
        or not 1 <= len(limitations) <= 32
        or any(
            not isinstance(item, str) or not 1 <= len(item) <= 512
            for item in limitations
        )
    ):
        raise InboxError("limitations must contain 1 to 32 bounded strings")


class SQLiteInbox:
    """SQLite-backed OIX inbox and approval queue.

    Trust is opt-in: callers must explicitly add a verified signed agent card.
    For task/evidence messages, inbox acceptance and creation of the
    approval-gated work item occur in one SQLite transaction.
    """

    def __init__(
        self,
        database: str | Path,
        local_agent_id: str,
        policy: CapabilityPolicy | None = None,
        *,
        busy_timeout_ms: int = 5000,
    ) -> None:
        if not isinstance(local_agent_id, str) or not local_agent_id.strip():
            raise ValueError("local_agent_id must be non-empty")
        if not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        self.database = str(database)
        self.local_agent_id = local_agent_id
        self.policy = policy or CapabilityPolicy()
        self.busy_timeout_ms = busy_timeout_ms
        path = Path(self.database)
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError("inbox database path must not traverse a symlink")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            try:
                descriptor = os.open(self.database, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                os.chmod(path, 0o600)
            else:
                os.close(descriptor)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS trusted_peers (
                    agent_id TEXT PRIMARY KEY,
                    signed_card_json TEXT NOT NULL,
                    trusted_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inbox_messages (
                    sender TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    PRIMARY KEY(sender, message_id),
                    UNIQUE(sender, nonce)
                );
                CREATE TABLE IF NOT EXISTS inbound_work (
                    work_id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    work_type TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    decided_at INTEGER,
                    UNIQUE(sender, message_id),
                    FOREIGN KEY(sender, message_id)
                        REFERENCES inbox_messages(sender, message_id)
                );
                CREATE INDEX IF NOT EXISTS idx_inbound_work_status
                    ON inbound_work(status, created_at);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=self.busy_timeout_ms / 1000)
        db.row_factory = sqlite3.Row
        db.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _validate_card(signed_card: dict[str, Any]) -> str:
        if not isinstance(signed_card, dict) or set(signed_card) != {"card", "signature"}:
            raise InboxError("agent card envelope has an invalid shape")
        card = signed_card.get("card")
        required = {
            "protocol", "protocol_version", "agent_id", "display_name",
            "public_key", "key_algorithm", "capabilities",
        }
        if not isinstance(card, dict) or set(card) != required:
            raise InboxError("agent card fields do not match OIX v0.1")
        if (
            not isinstance(card["display_name"], str)
            or not 1 <= len(card["display_name"]) <= 128
            or not isinstance(card["capabilities"], list)
            or len(card["capabilities"]) > 128
            or any(not isinstance(item, str) or not 1 <= len(item) <= 128
                   for item in card["capabilities"])
            or len(set(card["capabilities"])) != len(card["capabilities"])
        ):
            raise InboxError("agent card contains invalid display name or capabilities")
        if not verify_card(signed_card):
            raise InboxError("agent card signature or fingerprint is invalid")
        return card["agent_id"]

    def trust_peer(self, signed_card: dict[str, Any], *, trusted_at: int | None = None) -> str:
        """Explicitly trust a verified card; this is an operator-controlled action."""
        agent_id = self._validate_card(signed_card)
        timestamp = int(time.time()) if trusted_at is None else trusted_at
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise TypeError("trusted_at must be an integer timestamp")
        encoded = canonical_json(signed_card).decode("utf-8")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO trusted_peers(agent_id,signed_card_json,trusted_at)
                   VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                   signed_card_json=excluded.signed_card_json,
                   trusted_at=excluded.trusted_at""",
                (agent_id, encoded, timestamp),
            )
            db.commit()
        return agent_id

    def revoke_peer(self, agent_id: str) -> bool:
        """Remove local trust. Previously received records remain for audit."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "DELETE FROM trusted_peers WHERE agent_id=?", (agent_id,)
            ).rowcount
            db.commit()
        return bool(changed)

    def trusted_peer_public_key(self, agent_id: str) -> bytes:
        """Resolve an explicitly trusted peer's verified Ed25519 public key."""
        if not isinstance(agent_id, str) or not agent_id:
            raise UntrustedPeerError("peer agent ID is required")
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT signed_card_json FROM trusted_peers WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
        if row is None:
            raise UntrustedPeerError("sender is not in the local trusted-peer store")
        try:
            signed_card = json.loads(row["signed_card_json"])
            if self._validate_card(signed_card) != agent_id:
                raise UntrustedPeerError("stored trusted card is invalid")
            return _unb64(signed_card["card"]["public_key"])
        except (TypeError, ValueError, KeyError) as exc:
            raise UntrustedPeerError("stored trusted card is invalid") from exc

    def receive(
        self,
        envelope: dict[str, Any],
        *,
        now: int | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> InboxReceipt:
        """Validate and durably accept one envelope without executing its payload.

        When a caller supplies an existing SQLite connection, all inbox writes
        participate in that caller's transaction. This enables atomic
        one-time-prekey consumption and inbox acceptance in the same database.
        """
        current = int(time.time()) if now is None else now
        if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
            raise InboxError("message envelope has an invalid shape")
        body = envelope.get("body")
        if not isinstance(body, dict) or set(body) != _BODY_FIELDS:
            raise InboxError("message body fields do not match OIX v0.1")
        if not isinstance(body.get("payload"), dict):
            raise InboxError("message payload must be an object")
        message_type = body.get("type")
        if not isinstance(message_type, str) or message_type not in ALLOWED_TYPES:
            raise InboxError("unsupported message type")
        if message_type == "evidence.submit":
            _validate_evidence_submit_payload(body["payload"])
        message_id = body.get("message_id")
        try:
            if not isinstance(message_id, str) or str(uuid.UUID(message_id)) != message_id:
                raise ValueError
        except (ValueError, AttributeError) as exc:
            raise InboxError("message_id must be a canonical UUID") from exc
        try:
            encoded_envelope = canonical_json(envelope)
        except (TypeError, ValueError, RecursionError) as exc:
            raise InboxError("message is outside the OIX JSON data model") from exc
        if len(encoded_envelope) > MAX_MESSAGE_BYTES:
            raise InboxError("message exceeds the 1 MB limit")
        if not isinstance(current, int) or isinstance(current, bool):
            raise TypeError("now must be an integer Unix timestamp")
        if (
            not isinstance(body.get("issued_at"), int)
            or isinstance(body["issued_at"], bool)
            or body["issued_at"] < 0
            or not isinstance(body.get("expires_at"), int)
            or isinstance(body["expires_at"], bool)
            or body["expires_at"] < 1
        ):
            raise InboxError("message timestamps must be positive integer Unix seconds")
        sender = body.get("sender")
        if not isinstance(sender, str) or not sender:
            raise InboxError("sender is required")
        capability = body.get("requested_capability")
        if capability is not None and (
            not isinstance(capability, str) or not 1 <= len(capability) <= 128
        ):
            raise InboxError("requested_capability must be null or 1 to 128 characters")
        if not self.policy.permits(capability, message_type=message_type):
            raise InboxError("requested capability is not allowed by local policy")

        owns_connection = connection is None
        if connection is not None:
            if not connection.in_transaction:
                raise ValueError("caller-supplied inbox connection must have an active transaction")
            database_path = connection.execute("PRAGMA database_list").fetchone()[2]
            if Path(database_path).resolve() != Path(self.database).resolve():
                raise ValueError("caller-supplied inbox connection must use the inbox database")
        if owns_connection:
            with closing(self._connect()) as db:
                return self._receive_validated(
                    db, envelope, body, sender, message_id, message_type,
                    capability, encoded_envelope, current, manage_transaction=True,
                )
        return self._receive_validated(
            connection, envelope, body, sender, message_id, message_type,
            capability, encoded_envelope, current, manage_transaction=False,
        )

    def _receive_validated(
        self,
        db: sqlite3.Connection,
        envelope: dict[str, Any],
        body: dict[str, Any],
        sender: str,
        message_id: str,
        message_type: str,
        capability: str | None,
        encoded_envelope: bytes,
        current: int,
        *,
        manage_transaction: bool,
    ) -> InboxReceipt:
        digest = hashlib.sha256(encoded_envelope).hexdigest()
        body_json = canonical_json(body).decode("utf-8")
        envelope_json = encoded_envelope.decode("utf-8")
        if manage_transaction:
            db.execute("BEGIN IMMEDIATE")
        peer_row = db.execute(
            "SELECT signed_card_json FROM trusted_peers WHERE agent_id=?", (sender,)
        ).fetchone()
        if peer_row is None:
            raise UntrustedPeerError("sender is not in the local trusted-peer store")
        signed_card = json.loads(peer_row["signed_card_json"])
        if self._validate_card(signed_card) != sender:
            raise UntrustedPeerError("stored trusted card is invalid")
        public_key = _unb64(signed_card["card"]["public_key"])
        if not verify_for_recipient(
            envelope, public_key, self.local_agent_id, now=current
        ):
            raise InboxError("signature, sender, recipient, or validity check failed")

        prior = db.execute(
            """SELECT content_sha256 FROM inbox_messages
               WHERE sender=? AND message_id=?""",
            (sender, message_id),
        ).fetchone()
        if prior is not None:
            if prior["content_sha256"] != digest:
                raise InboxConflictError("message_id was reused with different content")
            existing_work = db.execute(
                "SELECT work_id,status FROM inbound_work WHERE sender=? AND message_id=?",
                (sender, message_id),
            ).fetchone()
            if manage_transaction:
                db.commit()
            return InboxReceipt(
                sender, message_id, message_type, True,
                existing_work["work_id"] if existing_work else None,
                existing_work["status"] if existing_work else None,
            )

        nonce_row = db.execute(
            "SELECT message_id FROM inbox_messages WHERE sender=? AND nonce=?",
            (sender, body["nonce"]),
        ).fetchone()
        if nonce_row is not None:
            raise ReplayError("sender nonce has already been accepted")

        db.execute(
            """INSERT INTO inbox_messages(
                sender,message_id,nonce,message_type,content_sha256,body_json,
                envelope_json,received_at
            ) VALUES(?,?,?,?,?,?,?,?)""",
            (
                sender, message_id, body["nonce"], message_type, digest,
                body_json, envelope_json, current,
            ),
        )
        work_id: str | None = None
        work_status: str | None = None
        if message_type in {"task.request", "evidence.submit"}:
            work_id = str(uuid.uuid4())
            work_status = (
                "pending_approval" if message_type == "task.request" else "pending_review"
            )
            db.execute(
                """INSERT INTO inbound_work(
                    work_id,sender,message_id,work_type,capability,payload_json,
                    status,created_at
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    work_id, sender, message_id, message_type, capability,
                    canonical_json(body["payload"]).decode("utf-8"), work_status, current,
                ),
            )
        if manage_transaction:
            db.commit()
        return InboxReceipt(sender, message_id, message_type, False, work_id, work_status)

    def pending_work(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with closing(self._connect()) as db:
            rows = db.execute(
                """SELECT work_id,sender,message_id,work_type,capability,payload_json,
                          status,created_at
                   FROM inbound_work
                   WHERE status IN ('pending_approval','pending_review')
                   ORDER BY created_at,work_id LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                "work_id": row["work_id"], "sender": row["sender"],
                "message_id": row["message_id"], "work_type": row["work_type"],
                "capability": row["capability"], "payload": json.loads(row["payload_json"]),
                "status": row["status"], "created_at": row["created_at"],
            }
            for row in rows
        ]

    def decide_work(self, work_id: str, *, approve: bool, decided_at: int | None = None) -> str:
        """Record an operator decision; approval does not itself execute or dispatch work."""
        if not isinstance(approve, bool):
            raise TypeError("approve must be a boolean")
        timestamp = int(time.time()) if decided_at is None else decided_at
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise TypeError("decided_at must be an integer timestamp")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM inbound_work WHERE work_id=?", (work_id,)
            ).fetchone()
            if row is None:
                db.rollback()
                raise WorkStateError("inbound work item does not exist")
            if row["status"] not in {"pending_approval", "pending_review"}:
                db.rollback()
                raise WorkStateError("inbound work item already has a decision")
            status = "approved" if approve else "rejected"
            db.execute(
                "UPDATE inbound_work SET status=?,decided_at=? WHERE work_id=?",
                (status, timestamp, work_id),
            )
            db.commit()
        return status
