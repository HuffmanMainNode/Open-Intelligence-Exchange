import copy

import pytest

from oix.discovery import create_announcement
from oix.gossip import (
    GossipError,
    GossipLedger,
    GossipPolicy,
    plan_gossip_forwarding,
)
from oix.identity import generate_identity, load_card, load_private_key
from oix.discovery_exchange import create_exchange_batch


NOW = 1_700_000_000


def make_peer(tmp_path, name):
    identity_dir = tmp_path / name.lower().replace(" ", "-")
    generate_identity(identity_dir, name, ["public.research"])
    return load_private_key(identity_dir), load_card(identity_dir / "agent-card.json")


def peer_id(card):
    return card["card"]["agent_id"]


def make_batch(tmp_path, sequence=1):
    key, card = make_peer(tmp_path, "Source")
    announcement = create_announcement(
        key, card, ["https://source.example.org/oix"], sequence=sequence, now=NOW
    )
    return create_exchange_batch([{"announcement": announcement, "card": card}], now=NOW)


def make_destinations(tmp_path, count):
    return [peer_id(make_peer(tmp_path, f"Destination {i}")[1]) for i in range(count)]


def test_gossip_plans_only_operator_approved_peers_and_excludes_sender(tmp_path):
    batch = make_batch(tmp_path)
    peers = make_destinations(tmp_path, 5)
    inbound = peers[0]
    approved = peers[1:]
    ledger = GossipLedger(tmp_path / "gossip.sqlite3")
    result = plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=inbound,
        operator_approved_peer_ids=[inbound, *approved],
        hop_count=0, now=NOW + 1, policy=GossipPolicy(max_fanout=2),
    )
    assert result["status"] == "planned"
    assert len(result["destinations"]) == 2
    assert inbound not in result["destinations"]
    assert result["hop_count"] == 1
    assert result["trust_state"] == "discovered_untrusted"


def test_gossip_rejects_invalid_signature_before_reserving_any_forward(tmp_path):
    batch = make_batch(tmp_path)
    batch["exchange"]["records"][0]["announcement"]["signature"] = "invalid"
    destinations = make_destinations(tmp_path, 2)
    ledger = GossipLedger(tmp_path / "gossip.sqlite3")
    with pytest.raises(GossipError, match="failed signature"):
        plan_gossip_forwarding(
            batch, ledger, inbound_peer_id=None,
            operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
        )
    with ledger._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM gossip_seen").fetchone()[0] == 0


def test_gossip_deduplicates_same_signed_batch_across_calls(tmp_path):
    batch = make_batch(tmp_path)
    destinations = make_destinations(tmp_path, 2)
    ledger = GossipLedger(tmp_path / "gossip.sqlite3")
    first = plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
    )
    second = plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 2,
    )
    assert first["status"] == "planned"
    assert second["status"] == "duplicate"
    assert second["destinations"] == []


def test_gossip_enforces_hop_fanout_and_candidate_limits(tmp_path):
    batch = make_batch(tmp_path)
    destinations = make_destinations(tmp_path, 4)
    ledger = GossipLedger(tmp_path / "gossip.sqlite3")
    stopped = plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=4, now=NOW + 1,
        policy=GossipPolicy(max_hops=4),
    )
    assert stopped["status"] == "hop_limit"
    with pytest.raises(GossipError, match="candidate list"):
        plan_gossip_forwarding(
            batch, ledger, inbound_peer_id=None,
            operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
            policy=GossipPolicy(max_candidates=2),
        )


def test_gossip_enforces_per_peer_hourly_quota_and_cancellation(tmp_path):
    batch = make_batch(tmp_path, sequence=1)
    destinations = make_destinations(tmp_path, 2)
    ledger = GossipLedger(tmp_path / "gossip.sqlite3")
    policy = GossipPolicy(max_fanout=2, per_peer_hourly_limit=1)
    result = plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
        policy=policy,
    )
    assert len(result["destinations"]) == 2
    digest = result["batch_sha256"]
    ledger.cancel(digest, result["destinations"][0])
    with pytest.raises(GossipError, match="no pending"):
        ledger.cancel(digest, result["destinations"][0])
    with pytest.raises(GossipError, match="no pending"):
        ledger.mark_sent(digest, result["destinations"][0])
    ledger.mark_sent(digest, result["destinations"][1])
    second = plan_gossip_forwarding(
        make_batch(tmp_path, sequence=2), ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 2,
        policy=policy,
    )
    assert second["destinations"] == [result["destinations"][0]]
    assert second["blocked"][result["destinations"][1]] == "hourly_quota"


def test_gossip_rejects_malformed_operator_peer_ids(tmp_path):
    ledger = GossipLedger(tmp_path / "gossip.sqlite3")
    with pytest.raises(GossipError, match="fingerprints"):
        ledger.reserve(
            "a" * 64, ["not-a-peer"], now=NOW, ttl_seconds=60,
            max_fanout=2, per_peer_hourly_limit=5,
        )


def test_gossip_policy_rejects_unsafe_limits():
    with pytest.raises(GossipError):
        GossipPolicy(max_fanout=99)
    with pytest.raises(GossipError):
        GossipPolicy(per_peer_hourly_limit=1000)
