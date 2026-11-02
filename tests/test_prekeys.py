from __future__ import annotations

import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from oix.envelope import create_message
from oix.identity import generate_identity, load_private_key
from oix.prekeys import (
    PreKeyError,
    SQLitePreKeyStore,
    create_prekey_bundle,
    encrypt_prekey_envelope,
    verify_prekey_bundle,
)


def _agent(tmp_path, name):
    directory = tmp_path / name
    card = generate_identity(directory, name, [])
    return load_private_key(directory), card["card"]["agent_id"], card


def _pair(tmp_path):
    sender_key, sender_id, _ = _agent(tmp_path, "sender")
    recipient_key, recipient_id, _ = _agent(tmp_path, "recipient")
    store = SQLitePreKeyStore(tmp_path / "recipient-prekeys.sqlite3")
    now = int(time.time())
    bundle = create_prekey_bundle(store, recipient_key, count=4, now=now)
    message = create_message(sender_key, recipient_id, "task.request", {"task": "public research"})
    return sender_key, sender_id, recipient_key, recipient_id, store, bundle, message, now


def test_signed_one_time_prekey_bundle_encrypts_and_consumes_once(tmp_path):
    sender_key, sender_id, recipient_key, recipient_id, store, bundle, message, now = _pair(tmp_path)
    assert verify_prekey_bundle(bundle, recipient_key.public_key().public_bytes_raw(), now=now)
    assert store.available_count(now=now) == 4
    assert all("private_key" not in key for key in bundle["body"]["keys"])

    encrypted = encrypt_prekey_envelope(
        message, bundle, recipient_key.public_key().public_bytes_raw(), now=now
    )
    decrypted = store.consume_and_decrypt(
        encrypted,
        recipient_key.public_key().public_bytes_raw(),
        sender_key.public_key().public_bytes_raw(),
        recipient_id,
        now=now,
    )
    assert decrypted == message
    assert store.available_count(now=now) == 3
    with pytest.raises(PreKeyError, match="missing or already consumed"):
        store.consume_and_decrypt(
            encrypted,
            recipient_key.public_key().public_bytes_raw(),
            sender_key.public_key().public_bytes_raw(),
            recipient_id,
            now=now,
        )


def test_invalid_ciphertext_does_not_consume_prekey(tmp_path):
    sender_key, _, recipient_key, recipient_id, store, bundle, message, now = _pair(tmp_path)
    encrypted = encrypt_prekey_envelope(
        message, bundle, recipient_key.public_key().public_bytes_raw(), now=now
    )
    changed = json.loads(json.dumps(encrypted))
    changed["ciphertext"] = ("A" if changed["ciphertext"][0] != "A" else "B") + changed["ciphertext"][1:]
    with pytest.raises(PreKeyError, match="authentication failed"):
        store.consume_and_decrypt(
            changed,
            recipient_key.public_key().public_bytes_raw(),
            sender_key.public_key().public_bytes_raw(),
            recipient_id,
            now=now,
        )
    assert store.available_count(now=now) == 4


def test_wrong_sender_or_recipient_cannot_consume_prekey(tmp_path):
    sender_key, _, recipient_key, recipient_id, store, bundle, message, now = _pair(tmp_path)
    wrong_key, _, _ = _agent(tmp_path, "wrong")
    encrypted = encrypt_prekey_envelope(
        message, bundle, recipient_key.public_key().public_bytes_raw(), now=now
    )
    with pytest.raises(PreKeyError, match="route, sender"):
        store.consume_and_decrypt(
            encrypted,
            recipient_key.public_key().public_bytes_raw(),
            wrong_key.public_key().public_bytes_raw(),
            recipient_id,
            now=now,
        )
    with pytest.raises(PreKeyError, match="route, sender"):
        store.consume_and_decrypt(
            encrypted,
            recipient_key.public_key().public_bytes_raw(),
            sender_key.public_key().public_bytes_raw(),
            "different-recipient",
            now=now,
        )
    assert store.available_count(now=now) == 4


def test_expired_or_wrongly_signed_prekey_bundle_is_rejected(tmp_path):
    _, _, recipient_key, recipient_id, store, bundle, message, now = _pair(tmp_path)
    wrong_key, _, _ = _agent(tmp_path, "wrong")
    assert not verify_prekey_bundle(
        bundle, wrong_key.public_key().public_bytes_raw(), now=now
    )
    assert not verify_prekey_bundle(
        bundle, recipient_key.public_key().public_bytes_raw(),
        now=bundle["body"]["expires_at"] + 1,
    )
    with pytest.raises(PreKeyError, match="invalid or expired"):
        encrypt_prekey_envelope(
            message,
            bundle,
            recipient_key.public_key().public_bytes_raw(),
            now=bundle["body"]["expires_at"] + 1,
        )


def test_prekey_created_before_expiry_can_decrypt_after_bundle_expiry(tmp_path):
    sender_key, _, recipient_key, recipient_id, store, _, _, now = _pair(tmp_path)
    short_store = SQLitePreKeyStore(tmp_path / "short-prekeys.sqlite3")
    bundle = create_prekey_bundle(short_store, recipient_key, count=1, ttl_seconds=60, now=now)
    message = create_message(sender_key, recipient_id, "agent.hello", {})
    encrypted = encrypt_prekey_envelope(
        message, bundle, recipient_key.public_key().public_bytes_raw(), now=now + 30
    )
    opened = short_store.consume_and_decrypt(
        encrypted,
        recipient_key.public_key().public_bytes_raw(),
        sender_key.public_key().public_bytes_raw(),
        recipient_id,
        now=now + 61,
    )
    assert opened == message


def test_concurrent_delivery_consumes_one_time_prekey_exactly_once(tmp_path):
    sender_key, _, recipient_key, recipient_id, store, bundle, message, now = _pair(tmp_path)
    encrypted = encrypt_prekey_envelope(
        message, bundle, recipient_key.public_key().public_bytes_raw(), now=now
    )

    def consume(_):
        local_store = SQLitePreKeyStore(store.database)
        try:
            return local_store.consume_and_decrypt(
                encrypted,
                recipient_key.public_key().public_bytes_raw(),
                sender_key.public_key().public_bytes_raw(),
                recipient_id,
                now=now,
            )
        except PreKeyError:
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(consume, range(8)))
    assert sum(item == message for item in outcomes) == 1
    assert store.available_count(now=now) == 3


def test_prekey_database_is_owner_only_on_posix(tmp_path):
    import os
    import stat

    if os.name != "posix":
        pytest.skip("POSIX permissions are not available")
    store = SQLitePreKeyStore(tmp_path / "private-prekeys.sqlite3")
    mode = stat.S_IMODE((tmp_path / "private-prekeys.sqlite3").stat().st_mode)
    assert mode == 0o600
    assert store.available_count(now=int(time.time())) == 0
