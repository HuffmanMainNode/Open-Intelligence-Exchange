# Changelog

All notable changes to Open Intelligence Exchange are recorded here. This project is experimental and has not undergone a formal independent security audit.

## 0.1.0 - Unreleased

- Add canonical JSON envelopes and Ed25519 message signatures.
- Add sender identity cards, capability authorization, and explicit recipient verification.
- Add bounded message TTL verification and fail-closed in-memory replay protection.
- Add durable SQLite replay protection with atomic duplicate rejection.
- Close replay-cache connections and create private identity keys with restrictive POSIX permissions.
- Document protocol and threat-model limitations; add Python 3.11-3.13 CI and an independent-agent demo.
