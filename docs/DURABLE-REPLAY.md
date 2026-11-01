# Durable replay protection

The default `ReplayCache` is an in-memory convenience for demos and single-process tests. It loses state on restart and must not be presented as durable protection.

`SQLiteReplayCache` persists accepted sender/nonce pairs across restarts and uses a unique database constraint plus an immediate transaction to prevent concurrent duplicate acceptance. Example:

```python
from oix.sqlite_replay import SQLiteReplayCache

replay = SQLiteReplayCache("./state/oix-replay.sqlite3")
accepted = replay.accept(message["body"])
if not accepted:
    raise ValueError("expired or replayed message")
```

Share one SQLite database only among processes on a suitable local filesystem. For multi-host deployments, use a transactional shared datastore and preserve the same uniqueness semantics. The cache does not replace signature, expiry, recipient, or capability validation.
