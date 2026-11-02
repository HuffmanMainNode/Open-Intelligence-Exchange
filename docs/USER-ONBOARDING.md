# Human onboarding

OIX is a local protocol library and command-line toolkit for agent identity, signed messages, peer trust and approval-gated inbox workflows. It is not a hosted relay, model or mandatory network.

## Install

Python 3.11+:

```bash
git clone https://github.com/HuffmanMainNode/Open-Intelligence-Exchange.git
cd Open-Intelligence-Exchange
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\\Scripts\\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q
ruff check .
bandit -q -r src
```

## Create a local agent identity

```bash
oix keygen --out ./agent-a --name "Research Agent" --capability "public.research"
oix card --identity ./agent-a
```

Protect the identity directory and private key. Do not commit it, upload it to a public repository or paste it into an AI conversation. The initial key files are not automatically encrypted. See the security documentation before using valuable identities.

## Sign and verify a message

```bash
oix sign --identity ./agent-a --to agent:recipient --type task.request --capability public.research --payload '{"task":"summarize public advisories"}' --out message.json
oix verify message.json --public-key ./agent-a/agent-card.json
```

The recipient must independently trust the sender's public key. A valid self-signed card is not a trust grant.

## Review before processing

The optional SQLite inbox places eligible requests into a pending-review state. An operator must inspect and approve the exact work item. A valid signature does not approve a task, establish factual accuracy or authorize unrelated side effects. See [durable inbox decision lookup](INBOX-DECISION-LOOKUP.md).

## Agent and developer guidance

- [Agent onboarding](AGENT-ONBOARDING.md)
- [Agent discovery](AGENT-DISCOVERY.md)
- [Mutual-TLS transport](MUTUAL-TLS-TRANSPORT.md)
- [Transactional inbox](TRANSACTIONAL-INBOX.md)
- [Security model](SECURITY.md)

The core library can be used without network transport. Experimental network components are not a production WAN mesh or a substitute for production PKI and key custody.
