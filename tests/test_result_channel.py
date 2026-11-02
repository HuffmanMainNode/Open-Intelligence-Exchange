import json
import sqlite3

import pytest

from oix.envelope import verify_message
from oix.identity import generate_identity, load_private_key
from oix.inbox import SQLiteInbox
from oix.result_channel import (
    ResultChannelError,
    ResultSchemaError,
    SQLiteResultPublisher,
)


def _identity(tmp_path, name):
    directory = tmp_path / name
    card = generate_identity(directory, name, [])
    return load_private_key(directory), card


def _result_database(path, *, sender, peer, task_id="task-123"):
    SQLiteInbox(path, peer)
    with sqlite3.connect(path) as db:
        db.execute(
            """
            CREATE TABLE oix_result_outbox (
                task_id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                request_message_id TEXT NOT NULL,
                terminal_status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending_approval'
                    CHECK(status IN (
                        'pending_approval','approved','signed','delivered','rejected'
                    )),
                created_at TEXT NOT NULL,
                decided_at TEXT,
                signed_envelope_json TEXT,
                signed_message_id TEXT,
                delivered_at TEXT,
                rejection_reason TEXT
            )
            """
        )
        payload = {
            "task_id": task_id,
            "request_message_id": "request-message-1",
            "status": "succeeded",
            "result": "A public-source summary.",
            "result_omitted": False,
        }
        db.execute(
            """
            INSERT INTO oix_result_outbox(
                task_id,sender,request_message_id,terminal_status,payload_json,
                status,created_at
            ) VALUES(?,?,?,?,?,'pending_approval','2026-11-01T00:00:00+00:00')
            """,
            (
                task_id, peer, payload["request_message_id"], "succeeded",
                json.dumps(payload),
            ),
        )


def test_result_requires_operator_approval_before_signing(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    _, peer_card = _identity(tmp_path, "peer")
    database = tmp_path / "shared.sqlite3"
    _result_database(
        database,
        sender=local_card["card"]["agent_id"],
        peer=peer_card["card"]["agent_id"],
    )
    publisher = SQLiteResultPublisher(
        database, local_card["card"]["agent_id"], local_key
    )
    assert publisher.pending()[0]["status"] == "pending_approval"
    with pytest.raises(ResultChannelError, match="operator-approved"):
        publisher.sign_approved("task-123")
    assert publisher.decide("task-123", approve=True) == "approved"


def test_signed_result_is_persisted_and_retries_reuse_exact_envelope(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    _, peer_card = _identity(tmp_path, "peer")
    database = tmp_path / "shared.sqlite3"
    _result_database(
        database,
        sender=local_card["card"]["agent_id"],
        peer=peer_card["card"]["agent_id"],
    )
    publisher = SQLiteResultPublisher(
        database, local_card["card"]["agent_id"], local_key
    )
    publisher.decide("task-123", approve=True)

    first = publisher.sign_approved("task-123")
    second = publisher.sign_approved("task-123")

    assert first == second
    assert first["body"]["type"] == "task.result"
    assert first["body"]["recipient"] == peer_card["card"]["agent_id"]
    assert verify_message(
        first,
        local_key.public_key().public_bytes_raw(),
    )
    queued = publisher.pending_delivery()
    assert len(queued) == 1
    assert queued[0]["envelope"] == first
    with sqlite3.connect(database) as db:
        row = db.execute(
            "SELECT status,signed_message_id,signed_envelope_json "
            "FROM oix_result_outbox WHERE task_id='task-123'"
        ).fetchone()
    assert row[0] == "signed"
    assert row[1] == first["body"]["message_id"]
    assert json.loads(row[2]) == first


def test_rejected_result_cannot_be_signed_or_redecided(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    _, peer_card = _identity(tmp_path, "peer")
    database = tmp_path / "shared.sqlite3"
    _result_database(
        database,
        sender=local_card["card"]["agent_id"],
        peer=peer_card["card"]["agent_id"],
    )
    publisher = SQLiteResultPublisher(
        database, local_card["card"]["agent_id"], local_key
    )
    assert publisher.decide("task-123", approve=False) == "rejected"
    with pytest.raises(ResultChannelError):
        publisher.sign_approved("task-123")
    with pytest.raises(ResultChannelError):
        publisher.decide("task-123", approve=True)


def test_delivery_acknowledgement_is_bound_to_persisted_message_id(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    _, peer_card = _identity(tmp_path, "peer")
    database = tmp_path / "shared.sqlite3"
    _result_database(
        database,
        sender=local_card["card"]["agent_id"],
        peer=peer_card["card"]["agent_id"],
    )
    publisher = SQLiteResultPublisher(
        database, local_card["card"]["agent_id"], local_key
    )
    publisher.decide("task-123", approve=True)
    envelope = publisher.sign_approved("task-123")
    message_id = envelope["body"]["message_id"]
    with pytest.raises(ResultChannelError, match="message ID mismatch"):
        publisher.mark_delivered("task-123", "wrong-id")
    assert publisher.mark_delivered("task-123", message_id) is True
    assert publisher.mark_delivered("task-123", message_id) is False
    assert publisher.pending_delivery() == []


def test_publisher_rejects_private_key_for_different_local_identity(tmp_path):
    first_key, first_card = _identity(tmp_path, "first")
    _, second_card = _identity(tmp_path, "second")
    database = tmp_path / "shared.sqlite3"
    SQLiteInbox(database, second_card["card"]["agent_id"])
    with pytest.raises(ValueError, match="does not belong"):
        SQLiteResultPublisher(
            database, second_card["card"]["agent_id"], first_key
        )


def test_publisher_fails_closed_without_shared_result_schema(tmp_path):
    key, card = _identity(tmp_path, "local")
    with pytest.raises(ResultSchemaError):
        SQLiteResultPublisher(
            tmp_path / "missing.sqlite3", card["card"]["agent_id"], key
        )
