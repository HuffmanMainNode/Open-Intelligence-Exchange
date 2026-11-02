# OIX Bounded Gossip Planner (Phase 14)

**Status:** Experimental local forwarding planner. It is not a live gossip transport or peer-discovery service.

## Purpose

Phase 14 adds a deterministic policy layer for forwarding verified discovery exchange batches among peers that an operator has already approved. It builds on Phase 12 signed discovery and Phase 13 bounded peer exchange.

## Forwarding rules

- The complete batch framing is checked against the Phase 13 schema and limits.
- Every nested announcement is independently verified against its signed agent card, including signature, identity binding, expiry, and endpoint syntax.
- Invalid or expired records cause the forwarding request to fail closed.
- The inbound sender is excluded from destinations.
- Candidate destinations must be supplied by the operator as approved Ed25519 agent fingerprints.
- Default fan-out is three, with an absolute implementation maximum of eight.
- Default hop limit is four, with an absolute maximum of eight.
- Each destination is subject to a local hourly forwarding quota.
- A durable SQLite ledger suppresses duplicate batches and reserves each planned destination once.
- A pending reservation can be marked sent after a transport reports success, or cancelled before sending.

## Important limitations

Hop count is mutable relay metadata. A malicious relay can reset it, so it is a loop-reduction and resource-control hint, not cryptographic proof or a security boundary. Batch deduplication uses the digest of the canonical outbound batch; independently repackaged batches may have different identifiers even when they contain the same signed records.

The ledger and quotas are local to one SQLite database and one installation. They do not coordinate limits across machines. An operator-approved peer list is an input to this planner; this module does not discover, enroll, or approve peers.

The planner does not open sockets, resolve or fetch endpoints, perform LAN discovery, run DHT, traverse NAT, or send messages. A future transport adapter must separately implement endpoint/IP restrictions, TLS identity binding, connection and frame limits, timeouts, rate limits, privacy controls, and explicit failure handling. Only call `mark_sent` after the transport confirms delivery; cancel a reservation only when no send occurred.

## Not implemented

No live gossip mesh, automatic peer scoring, multicast DNS, broadcast, WebSocket, HTTP polling, relay service, DHT, or background daemon is included. These remain separate phases with independent threat models and adversarial testing.
