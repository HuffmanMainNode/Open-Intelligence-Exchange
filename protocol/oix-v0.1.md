# OIX Protocol Specification v0.1

**Status:** Experimental draft. This document defines the behavior implemented by this repository's reference library. It is not a ratified internet standard.

## 1. Purpose

Open Intelligence Exchange (OIX) defines a small, transport-independent message envelope and evidence vocabulary for independent software agents. Implementations can exchange task requests, status, results, and provenance without requiring a shared model vendor, cloud account, or central OIX service.

OIX does not attempt to standardize model internals, private reasoning, or agent cognition. It does not request or transport hidden chain-of-thought. Optional summaries must be intentionally produced and authorized by the sending operator.

## 2. Protocol identifiers

- Protocol: `OIX`
- Version: `0.1`
- Signature algorithm: Ed25519
- Fingerprint: `ed25519:` followed by lowercase hexadecimal SHA-256 of the 32-byte raw public key
- Encoding: UTF-8 JSON using the restricted deterministic encoding described below

## 3. Canonical data model

The v0.1 canonical encoder sorts object keys, emits compact JSON, preserves UTF-8, and normalizes strings and keys to Unicode NFC. It rejects floating-point numbers, non-string keys, unsupported runtime values, duplicate keys after normalization, nesting deeper than 32, and arrays/objects larger than 10,000 members.

This restricted encoding is not a complete implementation of RFC 8785. Implementations MUST use the same canonical bytes when signing and verifying. Protocol fields requiring fractional values must be represented as strings or integer-scaled units.

## 4. Agent identity card

A signed agent card contains:
- `protocol`, `protocol_version`
- `agent_id`: public-key fingerprint
- `display_name`: informational, not an identity proof
- `public_key`: base64url-encoded raw Ed25519 public key
- `key_algorithm`: `ed25519`
- `capabilities`: sorted capability labels

The card signature is Ed25519 over canonical JSON bytes of the `card` object. A verifier MUST recompute the fingerprint and verify the signature. A valid card proves possession of the corresponding private key at signing time; it does not prove that the named operator or capability claims are honest.

## 5. Message envelope

An envelope has two top-level fields: `body` and `signature`. The signature is base64url-encoded Ed25519 over the canonical JSON bytes of `body`.

Required body fields:
- `protocol`: `OIX`
- `version`: `0.1`
- `message_id`: UUID
- `sender`: sender fingerprint
- `recipient`: opaque recipient identifier
- `type`: one of the defined message types
- `issued_at`, `expires_at`: Unix seconds as integers
- `nonce`: cryptographically random per-message value
- `requested_capability`: capability label or null
- `payload`: JSON object

Defined message types: `agent.hello`, `agent.hello_ack`, `task.request`, `task.accepted`, `task.progress`, `task.result`, `evidence.submit`, `error`, `delivery.receipt`.

Implementations MUST reject unknown protocol versions and message types, malformed signatures, expired messages, messages issued more than 60 seconds in the future, and envelopes larger than 1,000,000 canonical bytes. Senders MUST use TTLs from 1 to 86,400 seconds. Receivers MUST independently reject envelopes whose `expires_at - issued_at` is outside that same range.

## 6. Verification and replay protection

A receiver MUST:
1. Resolve the sender public key from a locally trusted or explicitly accepted agent card.
2. Verify the card fingerprint and card signature.
3. Verify envelope size, version, type, timestamps, TTL bounds, sender fingerprint, and message signature.
4. Check that the recipient matches the local agent or an explicitly supported broadcast target.
5. Reject a repeated `(sender, nonce)` pair until the message expires.
6. Require an explicit requested capability for `task.request` and `evidence.submit`, then apply local authorization independently of signature verification.
7. Treat payload strings and embedded instructions as untrusted data.

The default `ReplayCache` is bounded and in-memory and is suitable for examples and single-process tests only. The reference library also provides `SQLiteReplayCache`, which stores sender/nonce pairs durably and uses a database uniqueness constraint and transaction for atomic duplicate rejection. The CLI and example receiver currently use the in-memory cache. Multi-host deployments need a transactional shared datastore.

## 7. Authorization

A signature authenticates the message origin; it does not authorize the requested action. Implementations MUST apply local capability policy. Unknown capabilities are denied by default. Capability names are labels, not executable commands.

OIX core MUST NOT execute received code, invoke arbitrary shell commands, or grant file, network, payment, account, or administrative access merely because a message is signed. Consequential external actions require a separate permission system and human approval.

## 8. Evidence object

Evidence records SHOULD include:
- content SHA-256 and artifact size/media type
- source URI and source timestamp when known
- collection timestamp
- collector identifier and version
- collection method and version
- status: `observed`, `derived`, or `unverified`
- classification, concise machine-readable summary, and explicit limitations

`observed` means collected by the named method; it does not mean true. `derived` means computed from other observations and must preserve those provenance references. `unverified` means the artifact has not passed a documented validation procedure. A hash proves byte-level integrity relative to the supplied digest, not source authenticity or truth.

The reference inbox enforces the versioned `evidence.submit` payload in [evidence-submit.schema.json](../schemas/evidence-submit.schema.json). The payload is metadata-only: it carries an artifact digest, size, media type, and bounded summary, not raw artifact bytes or local filesystem paths. A non-null source URI must be HTTPS and contain no embedded credentials. The receiver validates this schema before creating an approval-gated `pending_review` work item. A valid message signature does not approve or verify the evidence.

## 9. Transport and discovery

The envelope is transport-neutral. Local files, standard input/output, authenticated HTTP, or peer-to-peer transports may carry it. Transport security and agent identity verification are separate controls. Network implementations SHOULD use authenticated TLS and MUST enforce size, timeout, rate, and authorization limits.

No central registry is required. Discovery records are hints, not trust anchors. Implementations MUST verify keys and apply local trust policy regardless of discovery source.

The experimental reference implementation defines a signed discovery announcement in [discovery-announcement.schema.json](schemas/discovery-announcement.schema.json). The Ed25519 signature covers the canonical announcement body and is bound to the exact signed agent card by its SHA-256 digest and agent fingerprint. Announcements contain a monotonically increasing per-agent sequence, random UUID, integer issue/expiry timestamps, one to eight HTTPS endpoint hints, and capability labels drawn from the signed card.

The reference verifier accepts TTLs from 1 to 3,600 seconds and permits at most 60 seconds of future clock skew. Its SQLite store rejects repeated or lower sequence numbers within that local store. Stored peers retain the explicit state discovered_untrusted. Discovery MUST NOT enroll a peer, install encryption keys, authorize messages, or execute tasks.

The reference implementation validates endpoint syntax only. It MUST NOT fetch or resolve endpoint hints during parsing. Any future connection adapter must separately implement DNS/IP restrictions, redirect policy, TLS identity binding, timeout and size limits, rate limits, and explicit local-network policy. SQLite sequence history is local and does not provide distributed rollback protection or a network revocation feed.

The experimental peer-exchange wrapper is defined by [discovery-exchange.schema.json](schemas/discovery-exchange.schema.json). It carries one to 64 announcement/card pairs in a canonical batch no larger than 512 KiB. The wrapper is transport-neutral and unauthenticated; each nested announcement and card MUST be verified independently. A batch digest is an integrity identifier for logs, not a signature or relay identity proof. Receivers may accept valid records and reject invalid or replayed entries independently. A batch wrapper MUST NOT grant trust, authorize capabilities, or trigger endpoint connections. Network transports MUST enforce their own frame-size, rate, timeout, and concurrency limits before parsing.

## 10. Interoperability

OIX is designed to map to existing agent and tool ecosystems. MCP provides a tool/resource interface; A2A provides agent discovery and task collaboration constructs. OIX does not claim full compatibility with either. See [INTEROPERABILITY.md](../docs/INTEROPERABILITY.md).

## 11. Security considerations

See [THREAT_MODEL.md](../docs/THREAT_MODEL.md) and [SECURITY.md](../SECURITY.md). The core v0.1 signed message is not confidential by itself. Optional versioned secure-envelope extensions provide authenticated encryption. The static-recipient wrapper does not provide forward secrecy. The one-time-prekey extension reduces later key-compromise exposure when consumed private keys are securely erased, but storage snapshots and backups may retain key material. Peer key rotation and revocation are local operator-controlled operations, not distributed revocation. No production network transport is included.


The Python library exposes `verify_for_recipient(...)` to combine signature/validity checks with an exact local-recipient check. Callers that use `verify_message(...)` directly must check the recipient themselves.

## 12. Secure transport extensions (version 1.0)

The reference implementation provides optional transport wrappers around an already-signed v0.1 message. These wrappers do not change the signed inner message contract.

### 12.1 Static-recipient secure envelope

The static-recipient wrapper uses ephemeral-sender X25519 key agreement, HKDF-SHA256, and ChaCha20-Poly1305. The recipient's X25519 public key is bound to its trusted Ed25519 identity by a signed, time-bounded certificate. This mode does not provide forward secrecy against later compromise of the recipient's static X25519 private key.

### 12.2 One-time-prekey envelope

A recipient may publish a signed, time-bounded bundle of one-time X25519 public keys. A sender verifies the bundle against the recipient's trusted Ed25519 identity, selects one key, and encrypts with a fresh ephemeral sender key. The receiver authenticates and decrypts the envelope, verifies the inner Ed25519 message, and atomically consumes the corresponding private prekey.

A receiver MUST:
1. Validate the signed prekey bundle before use and enforce the bundle expiry and key-count bounds.
2. Bind the encrypted envelope to the exact recipient, sender identity, prekey ID, ephemeral public key, nonce, and issue time using authenticated encryption.
3. Serialize consumption so concurrent deliveries cannot use the same prekey successfully.
4. Delete the one-time private key only after successful AEAD authentication and inner-message verification.
5. Preserve the prekey after failed authentication so unauthenticated ciphertext cannot burn a key.

The forward-secrecy benefit depends on secure deletion and absence of recoverable copies in backups, snapshots, logs, or storage remnants. Implementations SHOULD protect the local prekey database with encrypted storage and restrict filesystem permissions. Prekey bundle distribution and replenishment are out of scope for this transport-independent phase.

### 12.3 Durable delivery receipt

A `delivery.receipt` is an Ed25519-signed OIX message. It binds the acknowledged logical message ID to the SHA-256 digest of the exact encrypted transport envelope. A sender MUST verify the trusted recipient signature, expected route, message ID, digest, and receipt validity before recording delivery. The receipt is an authenticated peer assertion of durable acceptance, not proof of continued availability or physical storage guarantees.

The reference library provides these cryptographic and local persistence primitives only. It does not open sockets, discover peers, distribute bundles, or claim remote delivery.


## 13. Experimental bounded gossip planning

The reference implementation includes an experimental local gossip planner. It accepts a bounded peer-exchange batch, verifies every nested signed discovery announcement against its signed agent card, and computes forwarding reservations only for an operator-supplied approved-peer list. It excludes the inbound peer, applies a configurable fan-out and hop ceiling, suppresses duplicate canonical batch digests in a local SQLite ledger, and enforces local per-peer hourly quotas.

A forwarding reservation is not a delivery receipt. A transport adapter MUST call the sent-state transition only after its own transport reports success; it may cancel a reservation only when no send occurred. The planner does not open sockets, resolve endpoint hints, discover peers, or enroll trust.

Hop count is mutable metadata and MUST NOT be treated as cryptographic proof or a security boundary. The deduplication ledger and quotas are local to one database and do not coordinate across installations. Implementations MUST continue to treat all discovered peers as untrusted until a separate operator-controlled enrollment and authorization process succeeds. See [GOSSIP-PLANNER.md](../docs/GOSSIP-PLANNER.md).
