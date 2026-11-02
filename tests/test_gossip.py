import pytest

from oix import discovery, discovery_exchange, gossip, identity

NOW = 1_700_000_000


def make_peer(tmp_path, name):
    identity_dir = tmp_path / name.lower().replace(" ", "-")
    identity.generate_identity(identity_dir, name, ["public.research"])
    return identity.load_private_key(identity_dir), identity.load_card(identity_dir / "agent-card.json")


def peer_id(card):
    return card["card"]["agent_id"]


def make_batch(tmp_path, sequence=1):
    key, card = make_peer(tmp_path, f"Source {sequence}")
    announcement = discovery.create_announcement(
        key, card, ["https://source.example.org/oix"], sequence=sequence, now=NOW
    )
    return discovery_exchange.create_exchange_batch([{"announcement": announcement, "card": card}], now=NOW)


def make_destinations(tmp_path, count):
    return [peer_id(make_peer(tmp_path, f"Destination {i}")[1]) for i in range(count)]


def test_gossip_plans_only_operator_approved_peers_and_excludes_sender(tmp_path):
    batch = make_batch(tmp_path)
    peers = make_destinations(tmp_path, 5)
    inbound = peers[0]
    approved = peers[1:]
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    result = gossip.plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=inbound,
        operator_approved_peer_ids=[inbound, *approved],
        hop_count=0, now=NOW + 1, policy=gossip.GossipPolicy(max_fanout=2),
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
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    with pytest.raises(gossip.GossipError, match="failed signature"):
        gossip.plan_gossip_forwarding(
            batch, ledger, inbound_peer_id=None,
            operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
        )
    with ledger._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM gossip_seen").fetchone()[0] == 0


def test_gossip_deduplicates_same_signed_batch_across_calls(tmp_path):
    batch = make_batch(tmp_path)
    destinations = make_destinations(tmp_path, 2)
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    first = gossip.plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
    )
    second = gossip.plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 2,
    )
    assert first["status"] == "planned"
    assert second["status"] == "duplicate"
    assert second["destinations"] == []


def test_gossip_enforces_hop_fanout_and_candidate_limits(tmp_path):
    batch = make_batch(tmp_path)
    destinations = make_destinations(tmp_path, 4)
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    stopped = gossip.plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=4, now=NOW + 1,
        policy=gossip.GossipPolicy(max_hops=4),
    )
    assert stopped["status"] == "hop_limit"
    with pytest.raises(gossip.GossipError, match="candidate list"):
        gossip.plan_gossip_forwarding(
            batch, ledger, inbound_peer_id=None,
            operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
            policy=gossip.GossipPolicy(max_candidates=2),
        )


def test_gossip_enforces_per_peer_hourly_quota_and_cancellation(tmp_path):
    batch = make_batch(tmp_path, sequence=1)
    destinations = make_destinations(tmp_path, 2)
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    policy = gossip.GossipPolicy(max_fanout=2, per_peer_hourly_limit=1)
    result = gossip.plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 1,
        policy=policy,
    )
    assert len(result["destinations"]) == 2
    digest = result["batch_sha256"]
    ledger.cancel(digest, result["destinations"][0])
    with pytest.raises(gossip.GossipError, match="no pending"):
        ledger.cancel(digest, result["destinations"][0])
    with pytest.raises(gossip.GossipError, match="no pending"):
        ledger.mark_sent(digest, result["destinations"][0])
    ledger.mark_sent(digest, result["destinations"][1])
    second = gossip.plan_gossip_forwarding(
        make_batch(tmp_path, sequence=2), ledger, inbound_peer_id=None,
        operator_approved_peer_ids=destinations, hop_count=0, now=NOW + 2,
        policy=policy,
    )
    assert second["destinations"] == [result["destinations"][0]]
    assert second["blocked"][result["destinations"][1]] == "hourly_quota"


def test_gossip_rejects_malformed_operator_peer_ids(tmp_path):
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    with pytest.raises(gossip.GossipError, match="fingerprints"):
        ledger.reserve(
            "a" * 64, ["not-a-peer"], now=NOW, ttl_seconds=60,
            max_fanout=2, per_peer_hourly_limit=5,
        )


def test_gossip_policy_rejects_unsafe_limits():
    with pytest.raises(gossip.GossipError):
        gossip.GossipPolicy(max_fanout=99)
    with pytest.raises(gossip.GossipError):
        gossip.GossipPolicy(per_peer_hourly_limit=1000)


def test_no_approved_peers_does_not_consume_batch_deduplication(tmp_path):
    batch = make_batch(tmp_path)
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    empty = gossip.plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=[], hop_count=0, now=NOW + 1,
    )
    assert empty["status"] == "no_eligible_peers"
    peer = make_destinations(tmp_path, 1)
    planned = gossip.plan_gossip_forwarding(
        batch, ledger, inbound_peer_id=None,
        operator_approved_peer_ids=peer, hop_count=0, now=NOW + 2,
    )
    assert planned["status"] == "planned"


def test_gossip_ledger_prunes_expired_batch_and_old_quota_rows(tmp_path):
    ledger = gossip.GossipLedger(tmp_path / "gossip.sqlite3")
    peer = make_destinations(tmp_path, 1)[0]
    ledger.reserve(
        "a" * 64, [peer], now=NOW, ttl_seconds=60,
        max_fanout=1, per_peer_hourly_limit=2,
    )
    ledger.reserve(
        "b" * 64, [peer], now=NOW + 7200, ttl_seconds=60,
        max_fanout=1, per_peer_hourly_limit=2,
    )
    with ledger._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM gossip_seen").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM gossip_forward_plan").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM gossip_peer_quota").fetchone()[0] == 1
