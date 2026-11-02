from concurrent.futures import ThreadPoolExecutor

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



def test_concurrent_duplicate_acceptance_is_atomic(tmp_path):
    database = tmp_path / "shared-replay.sqlite3"
    caches = [SQLiteReplayCache(database) for _ in range(8)]
    message = body(nonce="c" * 24, expires_at=500)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda cache: cache.accept(message, now=100),
                caches,
            )
        )
    assert results.count(True) == 1
    assert results.count(False) == 7


def test_ten_thousand_accepts_close_every_connection(tmp_path, monkeypatch):
    cache = SQLiteReplayCache(tmp_path / "many-replay.sqlite3")
    opened = []
    original_connect = cache._connect

    class TrackingConnection:
        def __init__(self, connection):
            self.connection = connection
            self.closed = False

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def close(self):
            self.closed = True
            self.connection.close()

    def tracked_connect():
        connection = TrackingConnection(original_connect())
        opened.append(connection)
        return connection

    monkeypatch.setattr(cache, "_connect", tracked_connect)
    for index in range(10_000):
        cache.accept(
            body(nonce=f"{index:024d}", expires_at=20_000),
            now=100,
        )
    assert len(opened) == 10_000
    assert all(connection.closed for connection in opened)
