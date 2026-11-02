# OIX Bounded Peer Exchange (Phase 13)

**Status:** Experimental, transport-neutral reference implementation. This is a bounded record-exchange format, not a deployed peer-to-peer network.

## What this phase delivers

Phase 12 introduced signed, expiring discovery announcements. Phase 13 packages those announcements with their signed agent cards so independent installations can exchange them through any separately operated transport.

The batch wrapper is not an identity or trust claim. Each nested announcement remains independently verifiable against its card. A relay can forward records without being trusted to vouch for their contents.

## Batch limits and validation

- Protocol identifier: `OIX-DISCOVERY-EXCHANGE`, version `0.1`
- One to 64 records per batch
- Maximum canonical serialized batch size: 512 KiB
- Canonical UUID batch identifier
- Integer creation timestamp, with no more than 60 seconds of future skew
- Each record contains exactly one signed announcement and one signed agent card

The batch digest is SHA-256 over the canonical serialized exchange object. It is useful for logging and deduplication diagnostics; it is not a signature and does not authenticate the relay.

## Ingestion behavior

The receiver validates framing and resource limits before processing entries. It then verifies and stores each nested announcement independently. A malformed or replayed entry is rejected without discarding other valid entries in the same batch. The local SQLite discovery store enforces sequence monotonicity per agent within that installation.

Results report accepted identities, rejected indexes and reasons, counts, and the fixed trust state `discovered_untrusted`.

## Security boundaries

- The batch wrapper is unauthenticated and MUST be treated as untrusted input.
- Every nested announcement and card MUST be cryptographically verified.
- Discovery MUST NOT enroll peers, install keys, authorize capabilities, approve evidence, or execute tasks.
- No endpoint is resolved, fetched, probed, or contacted by this module.
- The receiver MUST apply network-level byte, connection, concurrency, and rate limits before passing data to this parser.
- The batch limit does not replace HTTP, socket, or message-frame limits at the transport layer.
- SQLite replay protection remains local to one store. It is not distributed consensus or global rollback protection.

## Not implemented

This phase does not implement gossip scheduling, peer scoring, multicast DNS, LAN broadcast, DHT, WebSocket, HTTP polling, relays, NAT traversal, or automatic connections. Those are separate adapters and require independent threat models, privacy controls, rate limiting, and endpoint safety review.

A future gossip adapter should use bounded fan-out, hop limits, per-peer quotas, deduplication caches, expiry propagation, and explicit operator-controlled peer seeds. It must never turn a discovered record into a trusted peer automatically.
