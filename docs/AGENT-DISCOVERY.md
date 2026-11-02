# OIX Agent Discovery (Phase 12)

**Status:** Experimental reference implementation. This is not a ratified discovery standard or a production peer directory.

## Purpose

Independent OIX agents need a way to publish endpoint hints without depending on a mandatory central registry. A discovery announcement binds a short-lived set of HTTPS endpoint hints and capability labels to an existing Ed25519 agent identity.

Discovery answers only: "Which endpoint hints did the holder of this key publish recently?"

It does not answer: "Is this peer trustworthy?", "Is this operator who they claim to be?", or "May this peer send tasks or evidence?"

## Signed announcement

The signed object contains an OIX protocol and version, public-key-derived agent_id, monotonic per-agent sequence, random announcement_id, integer issued_at and expires_at timestamps, SHA-256 digest of the exact signed agent card, one to eight HTTPS endpoint hints, and capability labels that must be a subset of the signed card's capabilities.

The Ed25519 signature covers the canonical JSON announcement body. Verification checks the signed agent card, public-key fingerprint, card digest, time bounds, endpoint syntax, and capability subset.

The default announcement TTL is five minutes. The maximum TTL is one hour. Verifiers allow at most 60 seconds of future clock skew. Implementations should use a reliable clock and refresh announcements before expiry.

## Local persistence and replay handling

SQLiteDiscoveryStore persists only the latest accepted announcement per agent identity. It rejects a repeated or lower sequence number and uses a transaction to serialize concurrent updates. Expired records are omitted from active listings; they remain in the database for audit and are not automatically deleted.

Every stored record has the fixed trust state discovered_untrusted. A newer valid announcement does not change that state.

## Trust and authorization boundary

Discovery is not enrollment. A caller MUST separately verify the signed agent card and announcement, apply an explicit local operator or policy decision before adding the peer to a trusted-peer store, apply capability authorization independently for every message and action, and re-check the peer's current key status and local policy when a connection is made.

Unknown peers MUST remain untrusted. A signed announcement MUST NOT automatically add a peer to the trusted identity registry, install encryption keys, authorize tasks, or trigger execution.

## Endpoint safety

The reference implementation accepts HTTPS endpoint syntax only. It rejects embedded credentials, fragments, malformed ports, control characters, duplicate endpoints, and oversized URLs.

**It does not fetch, resolve, probe, or connect to announced endpoints.** This is intentional: a discovery parser must not become an SSRF primitive. A future transport adapter must separately enforce DNS/IP policy, redirect restrictions, TLS identity binding, timeouts, response-size limits, and local-network policy at connection time. Endpoint syntax validation alone does not establish endpoint ownership or safety.

## Current limitations

- No multicast DNS, LAN broadcast, DHT, gossip, relay, or central directory adapter is implemented.
- No automatic endpoint probing or connection is implemented.
- No distributed sequence coordination or revocation feed is implemented.
- SQLite storage is local to one host and does not coordinate multiple installations.
- A valid signature proves control of the signing key, not operator identity, capability honesty, or endpoint ownership.
- Sequence numbers are protected only within a given local store. A fresh store cannot detect historical rollback without an independently trusted checkpoint.

The next maturity step is an independently reviewable transport/distribution adapter with explicit privacy, abuse, rate, and endpoint-validation controls. It must preserve the separation between discovery, trust, and authorization.
