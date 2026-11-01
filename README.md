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
| Message integrity | Ed25519 signatures over canonical envelope bytes |
| Replay defense | Bounded in-memory nonce cache with expiry |
| Authorization | Explicit capability allow-list |
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

Private-key note: private.key is stored unencrypted with owner-only permissions on POSIX systems. Protect the directory, do not sync it to public storage, and use encrypted disk or a secret manager for sensitive deployments. Key encryption and rotation workflows are not implemented yet.

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
- `src/oix/`: runnable Python implementation
- `examples/`: independent-agent demonstration
- `tests/`: protocol and security regression tests
- `docs/THREAT_MODEL.md`: risks, controls, known limits
- `docs/INTEROPERABILITY.md`: relationship to MCP and A2A

## Maturity and limitations

OIX v0.1 is experimental. It is not a security certification, production agent platform, or claim of full MCP/A2A conformance. The canonical JSON rules are a restricted deterministic subset, not a complete RFC 8785 implementation. The replay cache is in-memory; network transport, persistent replay storage, key rotation/revocation infrastructure, and production key custody are future work.

Use the protocol specification as the contract. Report ambiguity, interoperability problems, and security issues through the repository. See [SECURITY.md](SECURITY.md).

## Contributing

Start with a failing test, document the threat being addressed, keep dependencies small, and preserve offline operation. Never submit real secrets, private keys, private user data, or live exploit payloads.

## License

MIT. See [LICENSE](LICENSE).
