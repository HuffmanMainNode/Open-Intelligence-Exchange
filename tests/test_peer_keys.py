from __future__ import annotations

import pytest

from oix.envelope import create_message
from oix.identity import generate_identity, load_private_key
from oix.peer_keys import PeerKeyError, SQLitePeerKeyStore
from oix.secure_transport import encryption_key_fingerprint, generate_encryption_key


def _peer(tmp_path):
    directory = tmp_path / "peer"
    card = generate_identity(directory, "peer", [])
    return load_private_key(directory), card


def test_initial_key_install_and_idempotent_reinstall(tmp_path):
    signing_key, card = _peer(tmp_path)
    cert = generate_encryption_key(tmp_path / "enc-a", signing_key, now=1000)
    store = SQLitePeerKeyStore(tmp_path / "peers.sqlite3")
    key_id = store.install(cert, signing_key.public_key().public_bytes_raw(), now=1100)
    assert store.install(cert, signing_key.public_key().public_bytes_raw(), now=1100) == key_id
    assert store.active(card["card"]["agent_id"], now=1100) == cert
    assert [event["event"] for event in store.history(card["card"]["agent_id"])] == ["installed"]


def test_rotation_requires_approval_and_monotonic_certificate_time(tmp_path):
    signing_key, card = _peer(tmp_path)
    public = signing_key.public_key().public_bytes_raw()
    first = generate_encryption_key(tmp_path / "enc-a", signing_key, now=1000)
    second = generate_encryption_key(tmp_path / "enc-b", signing_key, now=2000)
    store = SQLitePeerKeyStore(tmp_path / "peers.sqlite3")
    store.install(first, public, now=1100)
    with pytest.raises(PeerKeyError, match="explicit operator approval"):
        store.install(second, public, now=2100)
    store.install(second, public, approve_rotation=True, now=2100)
    with pytest.raises(PeerKeyError, match="newer"):
        store.install(first, public, approve_rotation=True, now=2100)
    assert store.active(card["card"]["agent_id"], now=2100) == second
    events = [event["event"] for event in store.history(card["card"]["agent_id"])]
    assert events == ["installed", "rotated"]


def test_revocation_is_durable_and_revoked_key_cannot_be_reinstalled(tmp_path):
    signing_key, card = _peer(tmp_path)
    public = signing_key.public_key().public_bytes_raw()
    cert = generate_encryption_key(tmp_path / "enc-a", signing_key, now=1000)
    store = SQLitePeerKeyStore(tmp_path / "peers.sqlite3")
    store.install(cert, public, now=1100)
    agent_id = card["card"]["agent_id"]
    assert store.revoke(agent_id, now=1200, reason="operator trust withdrawal")
    assert store.active(agent_id, now=1200) is None
    with pytest.raises(PeerKeyError, match="revoked"):
        store.install(cert, public, now=1200)
    assert store.history(agent_id)[-1]["event"] == "revoked"


def test_invalid_or_expired_certificate_is_rejected(tmp_path):
    signing_key, _ = _peer(tmp_path)
    cert = generate_encryption_key(tmp_path / "enc-a", signing_key, now=1000, ttl_seconds=60)
    store = SQLitePeerKeyStore(tmp_path / "peers.sqlite3")
    with pytest.raises(PeerKeyError, match="invalid or expired"):
        store.install(cert, signing_key.public_key().public_bytes_raw(), now=1061)

def test_encrypt_for_peer_uses_only_active_registered_key(tmp_path):
    signing_key, card = _peer(tmp_path)
    peer_id = card["card"]["agent_id"]
    local_key, local_card = _peer(tmp_path / "local")
    cert = generate_encryption_key(tmp_path / "enc-a", signing_key, now=1000)
    store = SQLitePeerKeyStore(tmp_path / "peers.sqlite3")
    store.install(cert, signing_key.public_key().public_bytes_raw(), now=1100)
    message = create_message(local_key, peer_id, "agent.hello", {})
    secure = store.encrypt_for_peer(
        message, signing_key.public_key().public_bytes_raw(), now=1100
    )
    assert secure["header"]["recipient_key_fingerprint"] == encryption_key_fingerprint(cert)
    assert secure["header"]["recipient"] == peer_id
    assert local_card["card"]["agent_id"] == message["body"]["sender"]
    assert store.revoke(peer_id, now=1200, reason="test revocation")
    with pytest.raises(PeerKeyError, match="no active"):
        store.encrypt_for_peer(
            message, signing_key.public_key().public_bytes_raw(), now=1200
        )
