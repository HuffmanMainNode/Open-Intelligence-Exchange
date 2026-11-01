# Contributing to OIX

OIX should remain useful to independent developers with modest hardware and no paid infrastructure.

## Before opening a pull request

- Read the protocol specification and threat model.
- Open an issue for protocol changes that affect wire compatibility.
- Add tests for new behavior and regression cases.
- Run pytest, ruff check ., and bandit -q -r src.
- Update schemas and documentation when message contracts change.

## Engineering rules

- Keep the core transport-neutral and offline-capable.
- Do not add mandatory hosted services, API keys, telemetry, or model-provider dependencies.
- Never execute received payloads or treat peer content as trusted instructions.
- Keep authentication, authorization, and human approval separate.
- Use explicit versioning and reject unsupported versions.
- Do not add real private keys, credentials, personal data, or production secrets.
- Document limitations honestly. A passing test suite is not a security audit.

## Protocol changes

Wire-format changes require a version discussion before implementation. Add positive and negative fixtures, explain compatibility behavior, and update the JSON Schemas plus interoperability notes.
