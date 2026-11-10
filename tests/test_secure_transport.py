import json
import os
import stat

import pytest

from oix.canonical import decode_base64url
from oix.envelope import create_message, verify_message
from oix.identity import generate_identity, load_private_key, verify_card
from oix.secure_transport import (
    SecureEnvelopeError,
    decrypt_envelope,
    encrypt_envelope,
    generate_encryption_key,
    load_encryption_private_key,
    verify_encryption_certificate,
)


def _agent(tmp_path, name):
    directory = tmp_path / name
    card = generate_identity(directory, name, [])
    signing_key = load_private_key(directory)
    return directory, signing_key, card


def _secure_pair(tmp_path, *, cert_now=None, ttl_seconds=3600):
    _, sender_key, sender_card = _agent(tmp_path, "sender")
    receiver_dir, receiver_key, receiver_card = _agent(tmp_path, "receiver")
    certificate = generate_encryption_key(
        receiver_dir, receiver_key, now=cert_now, ttl_seconds=ttl_seconds
    )
    receiver_encryption_key = load_encryption_private_key(receiver_dir)
    return (
        sender_key,
        sender_card,
        receiver_key,
        receiver_card,
        receiver_encryption_key,
        certificate,
    )


def test_signed_oix_envelope_round_trips_through_authenticated_encryption(tmp_path):
    (
        sender_key, sender_card, receiver_key, receiver_card,
        receiver_encryption_key, certificate,
    ) = _secure_pair(tmp_path)
    sender_id = sender_card["card"]["agent_id"]
    receiver_id = receiver_card["card"]["agent_id"]
    message = create_message(
        sender_key, receiver_id, "task.request",
        {"task": "summarize public advisories"},
        capability="public.research",
    )

    encrypted = encrypt_envelope(
        message,
        certificate,
        receiver_key.public_key().public_bytes_raw(),
    )
    decrypted = decrypt_envelope(
        encrypted,
        receiver_encryption_key,
        certificate,
        receiver_key.public_key().public_bytes_raw(),
        sender_key.public_key().public_bytes_raw(),
        receiver_id,
    )

    assert decrypted == message
    assert encrypted["header"]["sender"] == sender_id
    assert encrypted["header"]["recipient"] == receiver_id
    assert "task" not in json.dumps(encrypted)


def test_ciphertext_and_authenticated_header_tampering_are_rejected(tmp_path):
    (
        sender_key, _, receiver_key, receiver_card,
        receiver_encryption_key, certificate,
    ) = _secure_pair(tmp_path)
    receiver_id = receiver_card["card"]["agent_id"]
    message = create_message(sender_key, receiver_id, "agent.hello", {})
    encrypted = encrypt_envelope(
        message, certificate, receiver_key.public_key().public_bytes_raw()
    )

    changed_ciphertext = json.loads(json.dumps(encrypted))
    changed_ciphertext["ciphertext"] = (
        ("A" if changed_ciphertext["ciphertext"][0] != "A" else "B")
        + changed_ciphertext["ciphertext"][1:]
    )
    with pytest.raises(SecureEnvelopeError, match="authentication failed"):
        decrypt_envelope(
            changed_ciphertext, receiver_encryption_key, certificate,
            receiver_key.public_key().public_bytes_raw(),
            sender_key.public_key().public_bytes_raw(), receiver_id,
        )

    changed_header = json.loads(json.dumps(encrypted))
    changed_header["header"]["sender"] = "ed25519:forged"
    with pytest.raises(SecureEnvelopeError):
        decrypt_envelope(
            changed_header, receiver_encryption_key, certificate,
            receiver_key.public_key().public_bytes_raw(),
            sender_key.public_key().public_bytes_raw(), receiver_id,
        )


def test_envelope_rejects_wrong_recipient_and_wrong_sender_key(tmp_path):
    (
        sender_key, _, receiver_key, receiver_card,
        receiver_encryption_key, certificate,
    ) = _secure_pair(tmp_path)
    _, other_key, other_card = _agent(tmp_path, "other")
    receiver_id = receiver_card["card"]["agent_id"]
    message = create_message(sender_key, receiver_id, "agent.hello", {})
    encrypted = encrypt_envelope(
        message, certificate, receiver_key.public_key().public_bytes_raw()
    )
    with pytest.raises(SecureEnvelopeError, match="another agent"):
        decrypt_envelope(
            encrypted, receiver_encryption_key, certificate,
            receiver_key.public_key().public_bytes_raw(),
            sender_key.public_key().public_bytes_raw(), other_card["card"]["agent_id"],
        )
    with pytest.raises(SecureEnvelopeError, match="trusted signing key"):
        decrypt_envelope(
            encrypted, receiver_encryption_key, certificate,
            receiver_key.public_key().public_bytes_raw(),
            other_key.public_key().public_bytes_raw(), receiver_id,
        )


def test_recipient_certificate_must_be_signed_by_trusted_agent_key(tmp_path):
    (
        sender_key, _, receiver_key, receiver_card,
        _, certificate,
    ) = _secure_pair(tmp_path)
    changed = json.loads(json.dumps(certificate))
    changed["body"]["public_key"] = (
        ("A" if changed["body"]["public_key"][0] != "A" else "B")
        + changed["body"]["public_key"][1:]
    )
    assert not verify_encryption_certificate(
        changed, receiver_key.public_key().public_bytes_raw()
    )
    message = create_message(
        sender_key, receiver_card["card"]["agent_id"], "agent.hello", {}
    )
    with pytest.raises(SecureEnvelopeError, match="certificate"):
        encrypt_envelope(
            message, changed, receiver_key.public_key().public_bytes_raw()
        )


def test_certificate_may_expire_after_message_was_created(tmp_path):
    import time

    issued = int(time.time())
    (
        sender_key, _, receiver_key, receiver_card,
        receiver_encryption_key, certificate,
    ) = _secure_pair(tmp_path, cert_now=issued - 1, ttl_seconds=10)
    receiver_id = receiver_card["card"]["agent_id"]
    message = create_message(sender_key, receiver_id, "agent.hello", {})
    encrypted = encrypt_envelope(
        message, certificate, receiver_key.public_key().public_bytes_raw(), now=issued
    )
    assert not verify_encryption_certificate(
        certificate, receiver_key.public_key().public_bytes_raw(), now=issued + 20
    )
    decrypted = decrypt_envelope(
        encrypted,
        receiver_encryption_key,
        certificate,
        receiver_key.public_key().public_bytes_raw(),
        sender_key.public_key().public_bytes_raw(),
        receiver_id,
        now=issued + 20,
    )
    assert decrypted == message


def test_encryption_key_files_are_private_and_never_overwritten(tmp_path):
    directory, signing_key, _ = _agent(tmp_path, "receiver")
    generate_encryption_key(directory, signing_key)
    assert len(load_encryption_private_key(directory).private_bytes_raw()) == 32
    if os.name == "posix":
        assert stat.S_IMODE((directory / "encryption.key").stat().st_mode) == 0o600
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        generate_encryption_key(directory, signing_key)


def test_encryption_certificate_rejects_expired_and_invalid_ttl(tmp_path):
    _, signing_key, _ = _agent(tmp_path, "receiver")
    directory = tmp_path / "receiver"
    certificate = generate_encryption_key(
        directory, signing_key, ttl_seconds=10, now=1000
    )
    assert not verify_encryption_certificate(
        certificate, signing_key.public_key().public_bytes_raw(), now=1011
    )
    with pytest.raises(ValueError, match="ttl_seconds"):
        generate_encryption_key(directory / "second", signing_key, ttl_seconds=0)

def test_decrypted_message_enters_normal_durable_oix_inbox(tmp_path):
    from oix.inbox import SQLiteInbox
    from oix.policy import CapabilityPolicy

    _, sender_key, sender_card = _agent(tmp_path, "sender")
    receiver_dir, receiver_key, receiver_card = _agent(tmp_path, "receiver")
    receiver_certificate = generate_encryption_key(receiver_dir, receiver_key)
    receiver_encryption_key = load_encryption_private_key(receiver_dir)
    receiver_id = receiver_card["card"]["agent_id"]
    database = tmp_path / "inbox.sqlite3"
    inbox = SQLiteInbox(
        database, receiver_id, CapabilityPolicy({"public.research"})
    )
    inbox.trust_peer(sender_card)
    signed = create_message(
        sender_key,
        receiver_id,
        "task.request",
        {"task": "summarize public advisories"},
        capability="public.research",
    )
    encrypted = encrypt_envelope(
        signed,
        receiver_certificate,
        receiver_key.public_key().public_bytes_raw(),
    )
    decrypted = decrypt_envelope(
        encrypted,
        receiver_encryption_key,
        receiver_certificate,
        receiver_key.public_key().public_bytes_raw(),
        sender_key.public_key().public_bytes_raw(),
        receiver_id,
    )
    receipt = inbox.receive(decrypted)
    assert receipt.message_type == "task.request"
    assert receipt.work_status == "pending_approval"
    assert inbox.pending_work()[0]["payload"]["task"] == "summarize public advisories"


def test_identity_and_message_reject_noncanonical_base64url(tmp_path):
    _, sender_key, sender_card = _agent(tmp_path, "sender")
    _, receiver_key, receiver_card = _agent(tmp_path, "receiver")

    changed_signature = json.loads(json.dumps(sender_card))
    changed_signature["signature"] += "!"
    assert not verify_card(changed_signature)

    changed_public_key = json.loads(json.dumps(sender_card))
    changed_public_key["card"]["public_key"] += "!"
    assert not verify_card(changed_public_key)

    message = create_message(
        sender_key, receiver_card["card"]["agent_id"], "agent.hello", {}
    )
    message["signature"] += "!"
    assert not verify_message(message, sender_key.public_key().public_bytes_raw())


def test_encryption_certificate_rejects_noncanonical_base64url(tmp_path):
    _, signing_key, _ = _agent(tmp_path, "receiver")
    directory = tmp_path / "receiver"
    certificate = generate_encryption_key(directory, signing_key)
    changed = json.loads(json.dumps(certificate))
    changed["signature"] += "!"
    assert not verify_encryption_certificate(
        changed, signing_key.public_key().public_bytes_raw()
    )



@pytest.mark.parametrize("value", ["A", "AB", "AA!", "AA="])
def test_decode_base64url_rejects_invalid_or_noncanonical_values(value):
    with pytest.raises(ValueError):
        decode_base64url(value)
