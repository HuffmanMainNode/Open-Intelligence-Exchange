# Interoperability: OIX, MCP, and A2A

OIX is intended to complement existing standards, not replace them.

## Model Context Protocol (MCP)

MCP standardizes how an AI application connects to tools, resources, and prompts. An MCP server can expose a local OIX library or a carefully permissioned OIX operation as a tool. MCP tool invocation and OIX agent-to-agent messaging solve different layers of the problem.

Possible mapping:
- MCP tool/resource metadata -> OIX capability descriptions and evidence references
- MCP tool call -> locally authorized OIX task request
- MCP tool result -> OIX task result with provenance metadata where available

An adapter must preserve the host application's consent and authorization model. It must not turn a remote OIX message into an unrestricted tool call.

## Agent2Agent (A2A)

A2A defines agent discovery and collaboration patterns, including agent cards and task-oriented interactions. OIX's agent card and message envelope are deliberately smaller and experimental.

Possible mapping:
- A2A Agent Card -> OIX identity card plus capability labels
- A2A task lifecycle -> OIX task.request / task.accepted / task.progress / task.result
- A2A artifacts -> OIX payload or evidence references

The fields and lifecycle semantics are not identical. An adapter must explicitly map states and preserve unknown fields rather than claiming wire compatibility.

## Adapter policy

No MCP or A2A adapter is included in v0.1. The core remains transport-neutral and independently testable. Future adapters should:
1. Pin a published specification version.
2. Add conformance fixtures from the upstream project.
3. Preserve identity and authorization boundaries.
4. Reject lossy or ambiguous conversions.
5. Document which optional features are unsupported.

## References

- MCP specification: https://modelcontextprotocol.io/specification/
- A2A project and specification: https://github.com/a2aproject/A2A
- OIX protocol: [oix-v0.1.md](../protocol/oix-v0.1.md)
