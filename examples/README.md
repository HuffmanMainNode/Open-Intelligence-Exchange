# OIX examples

## Independent process exchange

Run from the repository root after installing the package:

    python examples/agent_a.py

The sender creates two temporary identities, negotiates the OIX version and receiver capability, signs a task request, then launches agent_b.py as a separate process. The envelope crosses the process boundary through standard input. The receiver verifies the sender card and signature, checks recipient and capability policy, applies replay protection, and emits a JSON receipt.

The demonstration is local and intentionally does not open a TCP port. It does not execute task payloads or call a model API. The temporary private keys are removed when the process exits.

## Receiver contract

agent_b.py accepts:
- --identity: directory containing the receiver's agent-card.json and private.key
- --sender-card: signed agent card for the sender

It reads exactly one JSON envelope from stdin and emits a small receipt on stdout. Errors terminate the process with a non-zero exit status.
