from __future__ import annotations

from oix.identity import generate_identity, load_private_key
from oix.envelope import create_message
from oix.receipts import create_delivery_receipt, message_digest, verify_delivery_receipt


def _agent(tmp_path, name):
    directory = tmp_path / name
    card = generate_identity(directory, name, [])
    return load_private_key(directory), card["card"]["agent_id"]


def test_signed_receipt_binds_exact_sender_message_and_content(tmp_path):
    sender_key, sender_id = _agent(tmp_path, "sender")
    receiver_key, receiver_id = _agent(tmp_path, "receiver")
    original = create_message(sender_key, receiver_id, "task.result", {"result": "public"})
    digest = message_digest(original)
    receipt = create_delivery_receipt(
        receiver_key, sender_id, original["body"]["message_id"], digest, accepted_at=1234
    )
    assert verify_delivery_receipt(
        receipt,
        receiver_key.public_key().public_bytes_raw(),
        expected_recipient_agent_id=receiver_id,
        expected_sender_agent_id=sender_id,
        expected_message_id=original["body"]["message_id"],
        expected_content_digest=digest,
    )
    assert not verify_delivery_receipt(
        receipt,
        receiver_key.public_key().public_bytes_raw(),
        expected_recipient_agent_id=receiver_id,
        expected_sender_agent_id=sender_id,
        expected_message_id=original["body"]["message_id"],
        expected_content_digest="0" * 64,
    )
    assert not verify_delivery_receipt(
        receipt,
        sender_key.public_key().public_bytes_raw(),
        expected_recipient_agent_id=receiver_id,
        expected_sender_agent_id=sender_id,
        expected_message_id=original["body"]["message_id"],
        expected_content_digest=digest,
    )


def test_receipt_expiry_and_tampering_fail(tmp_path):
    sender_key, sender_id = _agent(tmp_path, "sender")
    receiver_key, receiver_id = _agent(tmp_path, "receiver")
    original = create_message(sender_key, receiver_id, "task.result", {"result": "public"})
    receipt = create_delivery_receipt(
        receiver_key, sender_id, original["body"]["message_id"],
        message_digest(original), accepted_at=1234,
    )
    assert not verify_delivery_receipt(
        receipt, receiver_key.public_key().public_bytes_raw(),
        expected_recipient_agent_id=receiver_id, expected_sender_agent_id=sender_id,
        expected_message_id=original["body"]["message_id"],
        expected_content_digest=message_digest(original), now=receipt["body"]["expires_at"] + 1,
    )
    changed = {**receipt, "body": {**receipt["body"], "payload": {
        **receipt["body"]["payload"], "durable": False,
    }}}
    assert not verify_delivery_receipt(
        changed, receiver_key.public_key().public_bytes_raw(),
        expected_recipient_agent_id=receiver_id, expected_sender_agent_id=sender_id,
        expected_message_id=original["body"]["message_id"],
        expected_content_digest=message_digest(original),
    )
