import json
import sqlite3
import time

import pytest

from oix.envelope import verify_message
from oix.identity import generate_identity, load_private_key
from oix.inbox import SQLiteInbox
from oix.prekeys import SQLitePreKeyStore, create_prekey_bundle
from oix.receipts import create_delivery_receipt, message_digest
from oix.result_channel import (
    ResultChannelError,
    ResultSchemaError,
    SQLiteResultPublisher,
)
from oix.secure_transport import (
    decrypt_envelope,
    generate_encryption_key,
    load_encryption_private_key,
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



def test_peer_revocation_rejects_undelivered_result_outbox_entries(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    _, peer_card = _identity(tmp_path, "peer")
    database = tmp_path / "shared.sqlite3"
    _result_database(
        database,
        sender=local_card["card"]["agent_id"],
        peer=peer_card["card"]["agent_id"],
    )
    inbox = SQLiteInbox(database, local_card["card"]["agent_id"])
    peer_id = inbox.trust_peer(peer_card)
    publisher = SQLiteResultPublisher(
        database, local_card["card"]["agent_id"], local_key
    )

    publisher.decide("task-123", approve=True)
    signed = publisher.sign_approved("task-123")
    assert publisher.pending_delivery()[0]["envelope"] == signed
    with sqlite3.connect(database) as db:
        db.execute(
            """
            INSERT INTO oix_result_outbox(
                task_id,sender,request_message_id,terminal_status,payload_json,
                status,created_at
            ) VALUES(?,?,?,?,?,'pending_approval','2026-11-01T00:00:00+00:00')
            """,
            (
                "task-pending", peer_card["card"]["agent_id"], "request-message-2",
                "succeeded", json.dumps({"task_id": "task-pending"}),
            ),
        )

    assert inbox.revoke_peer(peer_id) is True
    with sqlite3.connect(database) as db:
        statuses = dict(db.execute(
            "SELECT task_id,status FROM oix_result_outbox"
        ).fetchall())
        reasons = {
            row[0] for row in db.execute(
                "SELECT rejection_reason FROM oix_result_outbox"
            ).fetchall()
        }
    assert statuses == {"task-123": "rejected", "task-pending": "rejected"}
    assert reasons == {"recipient peer revoked"}
    assert publisher.pending_delivery() == []
    with pytest.raises(ResultChannelError, match="operator-approved"):
        publisher.sign_approved("task-pending")
    with pytest.raises(ResultChannelError, match="not pending"):
        publisher.decide("task-pending", approve=True)

    # Restoring trust must not revive previously rejected result deliveries.
    inbox.trust_peer(peer_card)
    assert publisher.pending_delivery() == []
    with pytest.raises(ResultChannelError, match="operator-approved"):
        publisher.sign_approved("task-123")


def test_delivery_acknowledgement_is_bound_to_persisted_message_id(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    peer_key, peer_card = _identity(tmp_path, "peer")
    peer_dir = tmp_path / "peer"
    peer_certificate = generate_encryption_key(peer_dir, peer_key)
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
    with pytest.raises(ResultChannelError, match="must be encrypted"):
        publisher.mark_delivered("task-123", {}, b"")
    secure = publisher.encrypt_approved(
        "task-123", peer_certificate, peer_key.public_key().public_bytes_raw()
    )
    digest = message_digest(secure)
    wrong_receipt = create_delivery_receipt(
        peer_key, local_card["card"]["agent_id"], "wrong-id", digest, accepted_at=1234
    )
    with pytest.raises(ResultChannelError, match="receipt signature or message binding"):
        publisher.mark_delivered(
            "task-123", wrong_receipt, peer_key.public_key().public_bytes_raw()
        )
    receipt = create_delivery_receipt(
        peer_key, local_card["card"]["agent_id"], message_id, digest, accepted_at=1234
    )
    assert publisher.mark_delivered(
        "task-123", receipt, peer_key.public_key().public_bytes_raw()
    ) is True
    assert publisher.mark_delivered(
        "task-123", receipt, peer_key.public_key().public_bytes_raw()
    ) is False
    assert publisher.pending_delivery() == []


def test_publisher_rejects_private_key_for_different_local_identity(tmp_path):
    first_key, _ = _identity(tmp_path, "first")
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

def test_persisted_envelope_tampering_is_detected_before_reuse_or_delivery(tmp_path):
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
    changed = json.loads(json.dumps(envelope))
    changed["body"]["payload"]["result"] = "tampered"
    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE oix_result_outbox SET signed_envelope_json=? WHERE task_id=?",
            (json.dumps(changed), "task-123"),
        )
    with pytest.raises(ResultChannelError, match="integrity checks"):
        publisher.sign_approved("task-123")
    with pytest.raises(ResultChannelError, match="integrity checks"):
        publisher.pending_delivery()

def test_result_is_encrypted_for_original_peer_and_persisted_before_delivery(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    peer_key, peer_card = _identity(tmp_path, "peer")
    peer_dir = tmp_path / "peer"
    peer_certificate = generate_encryption_key(peer_dir, peer_key)
    peer_encryption_key = load_encryption_private_key(peer_dir)
    peer_id = peer_card["card"]["agent_id"]
    database = tmp_path / "shared.sqlite3"
    _result_database(
        database,
        sender=local_card["card"]["agent_id"],
        peer=peer_id,
    )
    publisher = SQLiteResultPublisher(
        database, local_card["card"]["agent_id"], local_key
    )
    publisher.decide("task-123", approve=True)
    signed = publisher.sign_approved("task-123")

    secure = publisher.encrypt_approved(
        "task-123",
        peer_certificate,
        peer_key.public_key().public_bytes_raw(),
    )
    assert secure == publisher.encrypt_approved(
        "task-123",
        peer_certificate,
        peer_key.public_key().public_bytes_raw(),
    )
    assert "A public-source summary." not in json.dumps(secure)
    queued = publisher.pending_secure_delivery()
    assert len(queued) == 1
    assert queued[0]["envelope"] == secure
    decrypted = decrypt_envelope(
        secure,
        peer_encryption_key,
        peer_certificate,
        peer_key.public_key().public_bytes_raw(),
        local_key.public_key().public_bytes_raw(),
        peer_id,
    )
    assert decrypted == signed
    assert decrypted["body"]["payload"]["result"] == "A public-source summary."
    with sqlite3.connect(database) as db:
        row = db.execute(
            "SELECT secure_envelope_json,secure_key_fingerprint,status "
            "FROM oix_result_outbox WHERE task_id='task-123'"
        ).fetchone()
    assert json.loads(row[0]) == secure
    assert len(row[1]) == 64
    assert row[2] == "signed"


def test_result_cannot_be_encrypted_to_a_different_peer(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    _, peer_card = _identity(tmp_path, "peer")
    wrong_key, _ = _identity(tmp_path, "wrong-peer")
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
    publisher.sign_approved("task-123")
    wrong_certificate = generate_encryption_key(
        tmp_path / "wrong-peer-encryption", wrong_key
    )
    with pytest.raises(ResultChannelError, match="original trusted peer"):
        publisher.encrypt_approved(
            "task-123",
            wrong_certificate,
            wrong_key.public_key().public_bytes_raw(),
        )
    assert publisher.pending_secure_delivery() == []

def test_result_publisher_persists_prekey_envelope_and_requires_signed_receipt(tmp_path):
    local_key, local_card = _identity(tmp_path, "local")
    peer_key, peer_card = _identity(tmp_path, "peer")
    peer_id = peer_card["card"]["agent_id"]
    database = tmp_path / "shared.sqlite3"
    _result_database(
        database,
        sender=local_card["card"]["agent_id"],
        peer=peer_id,
    )
    publisher = SQLiteResultPublisher(
        database, local_card["card"]["agent_id"], local_key
    )
    publisher.decide("task-123", approve=True)
    signed = publisher.sign_approved("task-123")
    peer_store = SQLitePreKeyStore(tmp_path / "peer-prekeys.sqlite3")
    bundle = create_prekey_bundle(peer_store, peer_key, count=3)

    secure = publisher.encrypt_approved_with_prekey(
        "task-123", bundle, peer_key.public_key().public_bytes_raw()
    )
    retry = publisher.encrypt_approved_with_prekey(
        "task-123", bundle, peer_key.public_key().public_bytes_raw()
    )
    assert retry == secure
    assert secure["header"]["mode"] == "one_time_prekey"
    pending = publisher.pending_secure_delivery()
    assert len(pending) == 1
    assert pending[0]["envelope"] == secure

    opened = peer_store.consume_and_decrypt(
        secure,
        peer_key.public_key().public_bytes_raw(),
        local_key.public_key().public_bytes_raw(),
        peer_id,
    )
    assert opened == signed
    receipt = create_delivery_receipt(
        peer_key,
        local_card["card"]["agent_id"],
        signed["body"]["message_id"],
        message_digest(secure),
        accepted_at=int(time.time()),
    )
    assert publisher.mark_delivered(
        "task-123", receipt, peer_key.public_key().public_bytes_raw()
    )
    assert publisher.pending_secure_delivery() == []
