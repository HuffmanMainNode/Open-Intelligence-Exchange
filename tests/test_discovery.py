import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oix.discovery import (
    DiscoveryError,
    SQLiteDiscoveryStore,
    create_announcement,
    verify_announcement,
)
from oix.identity import generate_identity, load_card, load_private_key


def make_peer(tmp_path, name="Peer"):
    identity_dir = tmp_path / name.lower().replace(" ", "-")
    generate_identity(identity_dir, name, ["public.research", "evidence.review"])
    return load_private_key(identity_dir), load_card(identity_dir / "agent-card.json")


def announcement(key, card, *, sequence=1, now=1_700_000_000, ttl=300, endpoints=None):
    return create_announcement(
        key, card, endpoints or ["https://agent.example.org/oix"],
        sequence=sequence, now=now, ttl=ttl,
    )


def test_signed_announcement_binds_identity_card_and_capabilities(tmp_path):
    key, card = make_peer(tmp_path)
    record = announcement(key, card)
    assert verify_announcement(record, card, now=1_700_000_001)
    changed_card = json.loads(json.dumps(card))
    changed_card["card"]["display_name"] = "Impersonator"
    assert not verify_announcement(record, changed_card, now=1_700_000_001)


def test_announcement_rejects_wrong_private_key(tmp_path):
    _key, card = make_peer(tmp_path)
    with pytest.raises(DiscoveryError, match="does not match"):
        announcement(Ed25519PrivateKey.generate(), card)


@pytest.mark.parametrize("endpoint", [
    "http://agent.example.org/oix",
    "https://user:password@agent.example.org/oix",
    "https://agent.example.org/oix#fragment",
    "https://",
    "https://agent.example.org\\\\@evil.example/",
])
def test_unsafe_endpoint_hints_rejected(tmp_path, endpoint):
    key, card = make_peer(tmp_path)
    with pytest.raises(DiscoveryError):
        announcement(key, card, endpoints=[endpoint])


def test_expiry_ttl_and_sequence_validation(tmp_path):
    key, card = make_peer(tmp_path)
    with pytest.raises(DiscoveryError):
        announcement(key, card, ttl=3601)
    with pytest.raises(DiscoveryError):
        announcement(key, card, sequence=0)
    record = announcement(key, card, ttl=10)
    assert not verify_announcement(record, card, now=1_700_000_010)


def test_tampered_signature_and_payload_are_rejected(tmp_path):
    key, card = make_peer(tmp_path)
    record = announcement(key, card)
    record["announcement"]["endpoints"] = ["https://attacker.example"]
    assert not verify_announcement(record, card, now=1_700_000_001)


def test_store_keeps_discovered_peers_untrusted_and_rejects_replay(tmp_path):
    key, card = make_peer(tmp_path)
    store = SQLiteDiscoveryStore(tmp_path / "discovery.sqlite3")
    first = announcement(key, card, sequence=1)
    agent_id = store.record(first, card, now=1_700_000_001)
    peers = store.active(now=1_700_000_002)
    assert len(peers) == 1
    assert peers[0]["agent_id"] == agent_id
    assert peers[0]["trust_state"] == "discovered_untrusted"
    with pytest.raises(DiscoveryError, match="replay"):
        store.record(first, card, now=1_700_000_003)


def test_store_rejects_sequence_rollback_and_accepts_newer_announcement(tmp_path):
    key, card = make_peer(tmp_path)
    store = SQLiteDiscoveryStore(tmp_path / "discovery.sqlite3")
    store.record(announcement(key, card, sequence=2), card, now=1_700_000_001)
    with pytest.raises(DiscoveryError, match="rollback"):
        store.record(announcement(key, card, sequence=1), card, now=1_700_000_002)
    store.record(announcement(key, card, sequence=3), card, now=1_700_000_003)
    assert store.active(now=1_700_000_004)[0]["sequence"] == 3


def test_expired_records_are_not_returned(tmp_path):
    key, card = make_peer(tmp_path)
    store = SQLiteDiscoveryStore(tmp_path / "discovery.sqlite3")
    store.record(announcement(key, card, ttl=10), card, now=1_700_000_001)
    assert store.active(now=1_700_000_010) == []


def test_announcement_rejects_noncanonical_base64url(tmp_path):
    key, card = make_peer(tmp_path)
    record = announcement(key, card)
    record["signature"] += "!"
    assert not verify_announcement(record, card, now=1_700_000_001)
