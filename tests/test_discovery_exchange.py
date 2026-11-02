import copy

import pytest

from oix import discovery, discovery_exchange, identity

NOW = 1_700_000_000


def make_peer(tmp_path, name):
    identity_dir = tmp_path / name.lower()
    identity.generate_identity(identity_dir, name, ["public.research"])
    key = identity.load_private_key(identity_dir)
    card = identity.load_card(identity_dir / "agent-card.json")
    return key, card


def signed_record(tmp_path, name, sequence=1):
    key, card = make_peer(tmp_path, name)
    announcement = discovery.create_announcement(
        key, card, ["https://peer.example.org/oix"], sequence=sequence, now=NOW
    )
    return {"announcement": announcement, "card": card}


def test_batch_round_trip_ingests_independent_signed_records(tmp_path):
    batch = discovery_exchange.create_exchange_batch(
        [signed_record(tmp_path, "Peer A"), signed_record(tmp_path, "Peer B")],
        now=NOW,
    )
    store = discovery.SQLiteDiscoveryStore(tmp_path / "peers.sqlite3")
    result = discovery_exchange.ingest_exchange_batch(batch, store, now=NOW + 1)
    assert result["received"] == 2
    assert result["accepted_count"] == 2
    assert result["rejected_count"] == 0
    assert result["trust_state"] == "discovered_untrusted"
    assert len(store.active(now=NOW + 1)) == 2


def test_one_bad_record_does_not_discard_valid_records(tmp_path):
    valid = signed_record(tmp_path, "Good Peer")
    invalid = copy.deepcopy(signed_record(tmp_path, "Bad Peer"))
    invalid["announcement"]["signature"] = "not-a-signature"
    batch = discovery_exchange.create_exchange_batch([valid, invalid], now=NOW)
    store = discovery.SQLiteDiscoveryStore(tmp_path / "peers.sqlite3")
    result = discovery_exchange.ingest_exchange_batch(batch, store, now=NOW + 1)
    assert result["accepted_count"] == 1
    assert result["rejected_count"] == 1
    assert len(store.active(now=NOW + 1)) == 1


def test_batch_replay_cannot_duplicate_or_replace_peer(tmp_path):
    record = signed_record(tmp_path, "Peer")
    batch = discovery_exchange.create_exchange_batch([record], now=NOW)
    store = discovery.SQLiteDiscoveryStore(tmp_path / "peers.sqlite3")
    first = discovery_exchange.ingest_exchange_batch(batch, store, now=NOW + 1)
    second = discovery_exchange.ingest_exchange_batch(batch, store, now=NOW + 2)
    assert first["accepted_count"] == 1
    assert second["accepted_count"] == 0
    assert second["rejected_count"] == 1
    assert len(store.active(now=NOW + 2)) == 1


def test_batch_shape_protocol_clock_and_limits_are_enforced(tmp_path):
    record = signed_record(tmp_path, "Peer")
    batch = discovery_exchange.create_exchange_batch([record], now=NOW)
    altered = copy.deepcopy(batch)
    altered["exchange"]["protocol"] = "OTHER"
    with pytest.raises(discovery_exchange.ExchangeError, match="unsupported"):
        discovery_exchange.inspect_exchange_batch(altered, now=NOW + 1)
    with pytest.raises(discovery_exchange.ExchangeError, match="future"):
        discovery_exchange.inspect_exchange_batch(batch, now=NOW - 61)
    altered = copy.deepcopy(batch)
    altered["exchange"]["records"][0]["extra"] = True
    with pytest.raises(discovery_exchange.ExchangeError, match="exactly announcement"):
        discovery_exchange.inspect_exchange_batch(altered, now=NOW + 1)
    with pytest.raises(discovery_exchange.ExchangeError, match="1 to"):
        discovery_exchange.create_exchange_batch([], now=NOW)
    altered = copy.deepcopy(batch)
    altered["exchange"]["batch_id"] = "not-a-uuid"
    with pytest.raises(discovery_exchange.ExchangeError, match="canonical UUID"):
        discovery_exchange.inspect_exchange_batch(altered, now=NOW + 1)


def test_batch_size_is_bounded(tmp_path):
    record = signed_record(tmp_path, "Peer")
    record["card"] = {"padding": "x" * discovery_exchange.MAX_EXCHANGE_BYTES}
    with pytest.raises(discovery_exchange.ExchangeError, match="byte limit"):
        discovery_exchange.create_exchange_batch([record], now=NOW)


def test_batch_digest_is_stable_for_same_serialized_content(tmp_path):
    batch = discovery_exchange.create_exchange_batch([signed_record(tmp_path, "Peer")], now=NOW)
    _, first = discovery_exchange.inspect_exchange_batch(batch, now=NOW + 1)
    _, second = discovery_exchange.inspect_exchange_batch(batch, now=NOW + 1)
    assert first == second
