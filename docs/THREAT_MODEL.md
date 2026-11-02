# OIX Threat Model

## Security objective

Allow independently operated agents to exchange bounded, verifiable data while keeping identity, authorization, execution, and evidence trust separate.

## Assets

- Ed25519 private keys and identity continuity
- Agent operator permissions and local resources
- Message integrity and freshness
- Evidence provenance and content integrity
- Availability of local agent processes

## Adversaries

- Anonymous internet participants and malicious peers
- A compromised or impersonated agent
- A legitimate agent sending malicious or misleading payloads
- A poisoned discovery directory
- A prompt-injection document embedded in otherwise useful evidence
- A network observer or intermediary

## Threats and controls

| Threat | v0.1 control | Remaining limitation |
|---|---|---|
| Message tampering | Ed25519 signature over canonical body | No payload confidentiality |
| Key substitution | Fingerprint derived from public key; signed card | No global revocation service |
| Replay | In-memory cache for demos; SQLiteReplayCache for durable local storage | CLI and demo use in-memory cache; SQLite does not solve multi-host coordination |
| Expired/future messages | Timestamp checks and bounded TTL | Clock synchronization is an operator concern |
| Capability escalation | Separate local allow-list policy | Policy engine is intentionally minimal |
| Oversized payload | 1 MB envelope limit; canonical depth/member limits | Transport-level limits must also be configured |
| Prompt injection | Treat payload as untrusted data; no automatic execution | Downstream model integrations must preserve this boundary |
| Malicious code delivery | Core never executes payloads | Host application must not add unsafe execution |
| False evidence claims | Provenance fields and explicit status vocabulary | Hashes do not prove truth or source authenticity |
| Discovery poisoning | Discovery is not trust; verify keys locally | Discovery protocol not implemented in core |

## Trust boundaries

1. **Transport boundary:** receiving bytes does not authenticate the sender.
2. **Identity boundary:** a valid signature proves possession of a key, not the operator's real-world identity.
3. **Authorization boundary:** a valid signature does not authorize a requested capability.
4. **Content boundary:** signed payloads remain untrusted content.
5. **Evidence boundary:** a content hash establishes integrity relative to a digest, not truth.

## Key custody limitation

The v0.1 reference implementation writes the Ed25519 private key as raw, unencrypted bytes and applies owner-only POSIX permissions where supported. This is for local experimentation only. Protect the containing directory and host, use encrypted storage, and never commit or sync private keys to public repositories. Password-based key encryption and rotation are not implemented.

## Required deployment controls

A networked deployment should add authenticated TLS, strict request timeouts, connection and message rate limits, durable atomic replay storage, key rotation/revocation procedures, structured audit logs, resource quotas, and operator approval for consequential actions. Bind local development listeners to loopback by default. Do not expose a debug relay to the public internet.

## Out of scope for v0.1

- Confidentiality or end-to-end encryption
- Secure key storage hardware integration
- Key revocation distribution and recovery
- Persistent replay protection
- Production peer discovery or relay
- Full MCP or A2A conformance
- Formal verification or third-party security certification

## Reporting

Please follow [SECURITY.md](../SECURITY.md). Do not publish secrets, private keys, or unredacted sensitive data in issues.
