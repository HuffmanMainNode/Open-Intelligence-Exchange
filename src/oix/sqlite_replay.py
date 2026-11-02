"""Durable replay protection backed by SQLite.

Use one database shared by all workers on the same host or mounted volume.
For multi-host deployments, use a transactional shared database service.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing
import time
from pathlib import Path
from typing import Any


class SQLiteReplayCache:
    def __init__(self, database: str | Path, *, busy_timeout_ms: int = 5000) -> None:
        self.database = str(database)
        self.busy_timeout_ms = busy_timeout_ms
        if busy_timeout_ms < 1 or busy_timeout_ms > 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        with closing(self._connect()) as connection, connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS replay_entries (
                    sender TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY (sender, nonce)
                )
            """)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS replay_expiry_idx ON replay_entries(expires_at)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=self.busy_timeout_ms / 1000)
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        return connection

    def accept(self, body: dict[str, Any], *, now: int | None = None) -> bool:
        current = int(time.time()) if now is None else now
        sender = body.get("sender")
        nonce = body.get("nonce")
        expires_at = body.get("expires_at")
        if not isinstance(sender, str) or not sender:
            raise ValueError("sender must be a non-empty string")
        if not isinstance(nonce, str) or not 20 <= len(nonce) <= 128:
            raise ValueError("nonce must contain between 20 and 128 characters")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise TypeError("expires_at must be an integer timestamp")
        if expires_at < current:
            return False

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM replay_entries WHERE expires_at < ?", (current,))
            try:
                connection.execute(
                    "INSERT INTO replay_entries(sender, nonce, expires_at) VALUES (?, ?, ?)",
                    (sender, nonce, expires_at),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            connection.commit()
            return True
