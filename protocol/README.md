# OIX protocol assets

- oix-v0.1.md is the normative project draft for v0.1 behavior.
- schemas/message.schema.json describes the signed envelope.
- schemas/agent-card.schema.json describes the signed agent card.
- schemas/evidence.schema.json describes provenance records.

The schemas are interoperability aids. The Python reference implementation performs its own bounded validation and cryptographic checks; JSON Schema validation alone is not authentication or authorization.

Protocol changes that alter signed fields, canonicalization, message types, or version negotiation require a versioned specification update and regression fixtures.
