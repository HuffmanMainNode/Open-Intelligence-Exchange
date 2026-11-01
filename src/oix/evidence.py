"""Evidence provenance record helpers."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

STATUSES = {"observed", "verified", "unverified", "disputed", "unknown"}


def make_evidence(
    content: bytes,
    *,
    source_uri: str,
    collector_id: str,
    collector_version: str,
    method: str,
    status: str = "observed",
    source_timestamp: str | None = None,
    limitations: str = "",
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError("invalid evidence status")
    if not source_uri or not collector_id or not method:
        raise ValueError("source_uri, collector_id, and method are required")
    return {
        "evidence_id": "sha256:" + hashlib.sha256(content).hexdigest(),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "source_uri": source_uri,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source_timestamp": source_timestamp,
        "collector_id": collector_id,
        "collector_version": collector_version,
        "method": method,
        "status": status,
        "limitations": limitations,
    }
