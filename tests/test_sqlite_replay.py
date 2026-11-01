import pytest

from oix.sqlite_replay import SQLiteReplayCache


def body(sender="agent-a", nonce="n" * 24, expires_at=200):
    return {"sender": sender, "nonce": nonce, "expires_at": expires_at}


def test_replay_cache_persists_across_instances(tmp_path):
    database = tmp_path / "replay.sqlite3"
    first = SQLiteReplayCache(database)
    second = SQLiteReplayCache(database)
    assert first.accept(body(), now=100) is True
    assert second.accept(body(), now=100) is False


def test_expired_entries_are_rejected_and_pruned(tmp_path):
    cache = SQLiteReplayCache(tmp_path / "replay.sqlite3")
    assert cache.accept(body(expires_at=99), now=100) is False
    assert cache.accept(body(nonce="x" * 24), now=100) is True


def test_invalid_replay_record_is_rejected(tmp_path):
    cache = SQLiteReplayCache(tmp_path / "replay.sqlite3")
    with pytest.raises(ValueError):
        cache.accept({"sender": "", "nonce": "short", "expires_at": 100}, now=1)
