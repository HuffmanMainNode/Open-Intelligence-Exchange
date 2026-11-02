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

Defined message types: `agent.hello`, `agent.hello_ack`, `task.request`, `task.accepted`, `task.progress`, `task.result`, `evidence.submit`, `error`.

Implementations MUST reject unknown protocol versions and message types, malformed signatures, expired messages, messages issued more than 60 seconds in the future, and envelopes larger than 1,000,000 canonical bytes. Senders MUST use TTLs from 1 to 86,400 seconds. Receivers MUST independently reject envelopes whose `expires_at - issued_at` is outside that same range.

## 6. Verification and replay protection

A receiver MUST:
1. Resolve the sender public key from a locally trusted or explicitly accepted agent card.
2. Verify the card fingerprint and card signature.
3. Verify envelope size, version, type, timestamps, sender fingerprint, and message signature.
4. Check that the recipient matches the local agent or an explicitly supported broadcast target.
5. Reject a repeated `(sender, nonce)` pair until the message expires.
6. Apply authorization policy independently of signature verification.
7. Treat payload strings and embedded instructions as untrusted data.

The default `ReplayCache` is bounded and in-memory and is suitable for examples and single-process tests only. The reference library also provides `SQLiteReplayCache`, which stores sender/nonce pairs durably and uses a database uniqueness constraint and transaction for atomic duplicate rejection. The CLI and example receiver currently use the in-memory cache. Multi-host deployments need a transactional shared datastore.

## 7. Authorization

A signature authenticates the message origin; it does not authorize the requested action. Implementations MUST apply local capability policy. Unknown capabilities are denied by default. Capability names are labels, not executable commands.

OIX core MUST NOT execute received code, invoke arbitrary shell commands, or grant file, network, payment, account, or administrative access merely because a message is signed. Consequential external actions require a separate permission system and human approval.

## 8. Evidence object

Evidence records SHOULD include:
- content SHA-256
- source URI
- collection timestamp and source timestamp if known
- collector identifier and version
- collection method
- status: `observed`, `verified`, `unverified`, `disputed`, or `unknown`
- limitations and context

`observed` means collected by the named method; it does not mean true. `verified` requires a documented validation method and criteria. A hash proves byte-level integrity relative to the supplied digest, not source authenticity or truth.

## 9. Transport and discovery

The envelope is transport-neutral. Local files, standard input/output, authenticated HTTP, or peer-to-peer transports may carry it. Transport security and agent identity verification are separate controls. Network implementations SHOULD use authenticated TLS and MUST enforce size, timeout, rate, and authorization limits.

No central registry is required. Discovery records are hints, not trust anchors. Implementations MUST verify keys and apply local trust policy regardless of discovery source.

## 10. Interoperability

OIX is designed to map to existing agent and tool ecosystems. MCP provides a tool/resource interface; A2A provides agent discovery and task collaboration constructs. OIX does not claim full compatibility with either. See [INTEROPERABILITY.md](../docs/INTEROPERABILITY.md).

## 11. Security considerations

See [THREAT_MODEL.md](../docs/THREAT_MODEL.md) and [SECURITY.md](../SECURITY.md). v0.1 does not provide key revocation distribution, forward secrecy, encrypted payloads, persistent replay protection, or a production transport. Do not treat a signed message as confidential.


The Python library exposes `verify_for_recipient(...)` to combine signature/validity checks with an exact local-recipient check. Callers that use `verify_message(...)` directly must check the recipient themselves.