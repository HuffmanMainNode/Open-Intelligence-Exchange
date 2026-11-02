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
| Replay defense | Bounded in-memory cache, durable SQLite replay cache, and trusted-peer inbox replay controls |
| Authorization | Explicit capability allow-list and approval-gated durable inbound work queue |
| Evidence records | Provenance fields, content hashes, evidence status |
| CLI | Identity generation, card inspection, message signing and verification |
| Demo | Two local independent agent processes exchange and verify a signed message |
| Quality gates | pytest, Ruff, Bandit, GitHub Actions |

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

Private-key note: `private.key` is stored unencrypted and is created with owner-only POSIX mode `0600`; the containing directory is created with mode `0700` when newly created. Windows does not enforce POSIX mode bits. Protect the directory, do not sync it to public storage, and use encrypted disk or a secret manager for sensitive deployments. Key encryption and rotation workflows are not implemented yet.

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

## How an exchange works

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
- `protocol/schemas/`: JSON Schema contracts
- `src/oix/`: runnable Python implementation, including `SQLiteInbox` for explicit peer trust, durable receive, and approval-gated work
- `examples/`: independent-agent demonstration
- `tests/`: protocol and security regression tests
- `docs/THREAT_MODEL.md`: risks, controls, known limits
- `docs/INTEROPERABILITY.md`: relationship to MCP and A2A

## Maturity and limitations

OIX v0.1 is experimental. It is not a security certification, production agent platform, or claim of full MCP/A2A conformance. The canonical JSON rules are a restricted deterministic subset, not a complete RFC 8785 implementation. The CLI and two-process example use the in-memory cache for demonstration only. The library also provides `SQLiteReplayCache` for durable, atomic replay protection across restarts on a shared local database. See [DURABLE-REPLAY.md](docs/DURABLE-REPLAY.md). Network transport, encrypted payloads, distributed replay coordination, key rotation/revocation infrastructure, and production key custody remain future work. `SQLiteInbox` is a local receive primitive: it requires explicit trusted-card enrollment, persists task/evidence messages for operator approval/review, and never dispatches or executes payloads. See [TRANSACTIONAL-INBOX.md](docs/TRANSACTIONAL-INBOX.md).

Use the protocol specification as the contract. Report ambiguity, interoperability problems, and security issues through the repository. See [SECURITY.md](SECURITY.md).

## Contributing

Start with a failing test, document the threat being addressed, keep dependencies small, and preserve offline operation. Never submit real secrets, private keys, private user data, or live exploit payloads.

## License

MIT. See [LICENSE](LICENSE).
