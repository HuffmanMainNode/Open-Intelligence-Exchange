# Open Intelligence Exchange (OIX)

**Open protocols. Independent agents. Verifiable exchanges.**

OIX is an experimental open protocol and Python reference implementation for independent AI agents and their operators to exchange capability descriptions, task requests, results, and evidence with explicit verification and permission boundaries.

> Instead of passing out candy, we're passing out algorithms.

OIX is not a chatbot, hosted agent, model, or mandatory network. It is a small interoperability layer that projects can run locally, embed, fork, and extend. No OIX-operated server, paid API, model provider, or account is required for the core library.

## What is implemented in v0.1

| Capability | Implementation |
|---|---|
| Deterministic message encoding | Restricted canonical JSON; rejects floats and non-JSON values |
| Agent identity | Ed25519 keypair, public-key fingerprint, signed agent card |
| Message integrity | Ed25519 signatures over canonical message-body bytes |
| Confidentiality wrapper | Optional X25519 + HKDF-SHA256 + ChaCha20-Poly1305 secure envelope, bound to a trusted Ed25519 identity |
| One-time prekeys | Signed X25519 prekey bundles, ephemeral sender keys, and atomic single-use decryption with local private-key consumption |
| Peer key lifecycle | Local SQLite registry with explicit rotation approval, monotonic certificate timestamps, revocation, and audit history |
| Delivery receipts | Signed delivery.receipt messages bound to the exact encrypted-envelope digest and logical message ID |
| Experimental network transport | Bounded persistent mutual-TLS sessions, certificate URI SAN bound to OIX agent fingerprints, encrypted one-time-prekey envelopes, durable signed acknowledgements with per-message backpressure |
| Replay defense | Bounded in-memory cache, durable SQLite replay cache, and trusted-peer inbox replay controls |
| Authorization | Explicit capability allow-list and approval-gated durable inbound work queue |
| Evidence records | Strict metadata-only evidence.submit 1.0 schema, provenance, artifact hashes, limitations, and approval-gated review |
| Agent discovery | Signed expiring endpoint announcements, card binding, monotonic sequence checks, and SQLite discovery cache that preserves untrusted status |
| CLI | Identity generation, card inspection, message signing and verification |
| Demo | Two local independent agent processes exchange and verify a signed message |
| Quality gates | pytest, Ruff, Bandit, GitHub Actions |

See [Evidence Submission Schema](schemas/evidence-submit.schema.json) for the strict evidence payload contract. See [Agent Discovery](docs/AGENT-DISCOVERY.md) for signed, expiring endpoint hints and the discovery/trust boundary. See [Mutual-TLS Transport](docs/MUTUAL-TLS-TRANSPORT.md) for the experimental TCP adapter, setup requirements, and security boundaries. The core library remains usable without network transport.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e ".[dev]"
pytest
ruff check .
bandit -q -r src
```

Private-key note: `private.key` and optional `encryption.key` are stored unencrypted and are created with owner-only POSIX mode `0600`; identity directories use mode `0700`. Windows does not enforce POSIX mode bits. Protect the directory, do not sync it to public storage, and use encrypted disk or a secret manager for sensitive deployments. Automated key encryption and online key distribution are not implemented. A local SQLite peer-key registry supports operator-approved certificate rotation and revocation; it does not provide forward secrecy or production key custody.

Create an identity:

```bash
oix keygen --out ./agent-a --name "Research Agent" --capability "public.research"
oix card --identity ./agent-a
```

Sign and verify a message:

```bash
oix sign --identity ./agent-a --to agent:recipient --type task.request --capability public.research --payload '{"task":"summarize public advisories"}' --out message.json
oix verify message.json --public-key ./agent-a/agent-card.json
```

Run the local two-agent demo:

```bash
python examples/agent_a.py
```

See [Mutual-TLS Transport](docs/MUTUAL-TLS-TRANSPORT.md) for the experimental TCP adapter, setup requirements, and security boundaries. The core library remains usable without network transport.\n\n## How an exchange works

1. Each agent creates its own Ed25519 identity and signs its public agent card.
2. The initiating agent checks the peer's advertised protocol version and required capability labels.
3. The sender builds a bounded message envelope with a recipient, expiry, random nonce, payload, and requested capability.
4. The sender signs the canonical message body.
5. The receiver validates the sender card, message signature, timestamps, recipient, and replay state.
6. The receiver applies its own local capability allow-list. `task.request` and `evidence.submit` require an explicit requested capability. A valid signature alone never authorizes an action.
7. The receiver returns a receipt. The example does not execute the received payload.

The runnable demonstration launches the receiver as a separate Python process and passes the signed envelope over standard input. This proves a process boundary without requiring a hosted relay or opening a network port.

## Design principles

1. **Independent by default.** No central broker or registry is required.
2. **Cryptographic identity.** An agent identifier is derived from its Ed25519 public key, not its display name.
3. **Authentication is not authorization.** A valid signature does not grant capability access.
4. **Evidence travels with provenance.** Claims should be inspectable and independently checked.
5. **Received content is untrusted.** Messages are data, never executable instructions.
6. **No hidden-reasoning endpoint.** OIX exchanges task inputs, status, authorized evidence, outputs, and optional operator-approved summaries, not private chain-of-thought.
7. **Human control.** The reference implementation does not run shell commands, execute received code, or take external actions.

## Project map

- `protocol/oix-v0.1.md`: protocol contract and security requirements
- `protocol/schemas/`: JSON Schema contracts, including signed discovery announcements
- `src/oix/`: runnable Python implementation, including `SQLiteInbox`, `SQLiteResultPublisher`, and optional authenticated encryption in `secure_transport.py`
- `examples/`: independent-agent demonstration
- `tests/`: protocol and security regression tests
- `docs/THREAT_MODEL.md`: risks, controls, known limits
- `docs/INTEROPERABILITY.md`: relationship to MCP and A2A
- `docs/SECURE-ENVELOPES.md`: encrypted message wrapper, peer key lifecycle, signed delivery receipts, one-time prekeys, and threat boundaries
- `docs/AGENT-DISCOVERY.md`: signed discovery announcements, replay handling, endpoint limits, and trust separation

## Maturity and limitations

OIX v0.1 is experimental. It is not a security certification, production agent platform, or claim of full MCP/A2A conformance. The canonical JSON rules are a restricted deterministic subset, not a complete RFC 8785 implementation. The CLI and two-process example use the in-memory cache for demonstration only. The library also provides `SQLiteReplayCache` for durable, atomic replay protection across restarts on a shared local database. See [DURABLE-REPLAY.md](docs/DURABLE-REPLAY.md). Live network discovery distribution, endpoint probing, distributed replay coordination, automated key distribution, production key custody and live transport remain future work. The discovery reference library validates signed HTTPS endpoint hints and stores them locally as discovered_untrusted; it does not resolve, fetch, connect to, or enroll announced peers. See docs/AGENT-DISCOVERY.md. The optional one-time-prekey path provides a forward-secrecy-oriented design whose guarantees depend on private-key erasure and backup/storage behavior. Key rotation and revocation are local operator-controlled registry operations; delivery receipts are signed protocol objects and do not themselves transport messages. The optional `secure_transport.py` wrapper encrypts signed OIX messages with X25519, HKDF-SHA256, and ChaCha20-Poly1305, but it does not open sockets or integrate automatically with `SQLiteInbox`; callers decrypt first, then pass the inner message to the inbox. The current static recipient encryption key does not provide forward secrecy against later compromise. `SQLiteInbox` is a local receive primitive: it requires explicit trusted-card enrollment, persists task/evidence messages for operator approval/review, and never dispatches or executes payloads. The optional `SQLiteResultPublisher` stages OIX-originated Open-Swarm results for explicit operator approval, signs and persists the exact `task.result` envelope, and can encrypt and persist a wrapper addressed to the original peer's certified X25519 key before exposing it through `pending_secure_delivery()`. It never sends the message. It requires the shared SQLite result-outbox schema initialized by the Open-Swarm OIX handoff adapter. See [TRANSACTIONAL-INBOX.md](docs/TRANSACTIONAL-INBOX.md), [SIGNED-RESULT-CHANNEL.md](docs/SIGNED-RESULT-CHANNEL.md), and [SECURE-ENVELOPES.md](docs/SECURE-ENVELOPES.md).

Use the protocol specification as the contract. Report ambiguity, interoperability problems, and security issues through the repository. See [SECURITY.md](SECURITY.md).

## Contributing

Start with a failing test, document the threat being addressed, keep dependencies small, and preserve offline operation. Never submit real secrets, private keys, private user data, or live exploit payloads.

## License

MIT. See [LICENSE](LICENSE).
