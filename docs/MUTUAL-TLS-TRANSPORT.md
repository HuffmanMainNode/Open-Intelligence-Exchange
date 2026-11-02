# OIX mutual-TLS framed transport

Status: experimental transport adapter. The protocol remains usable without this module.

## Scope

The oix.transport module provides a bounded, one-message-per-connection TCP transport for encrypted OIX one-time-prekey envelopes. It uses Python standard ssl and asyncio libraries. The server requires a client certificate signed by a locally configured CA; clients validate the server certificate and hostname. TLS 1.2 or newer is required.

The transport does not replace OIX identity or authorization:
- TLS certificate validation protects the transport channel and authenticates a CA-authorized client certificate.
- The inner Ed25519 signature is checked against the receiver's explicitly trusted OIX peer card.
- The recipient identity, expiry, nonce, capability policy, and replay state are checked by the OIX inbox.
- A valid transport certificate does not automatically add an OIX agent to the trusted-peer store.
- A valid OIX signature does not authorize task execution. Inbound task requests remain pending operator approval.

## Receiver setup

Create an OIX identity and configure a TLS server certificate with a DNS or IP subject alternative name matching the hostname clients will use. Configure a CA trust bundle containing the CA that issues authorized client certificates.

Example:

    import asyncio
    import ssl

    from oix.identity import load_private_key
    from oix.inbox import SQLiteInbox
    from oix.policy import CapabilityPolicy
    from oix.prekeys import SQLitePreKeyStore
    from oix.transport import OIXMutualTLSServer

    identity_dir = "./receiver-identity"
    database = "./receiver.sqlite3"
    signing_key = load_private_key(identity_dir)

    inbox = SQLiteInbox(
        database,
        local_agent_id="REPLACE_WITH_RECEIVER_AGENT_ID",
        policy=CapabilityPolicy({"public.research"}),
    )
    prekeys = SQLitePreKeyStore(database)

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("./receiver-cert.pem", "./receiver-key.pem")
    tls.load_verify_locations(cafile="./authorized-client-ca.pem")
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.minimum_version = ssl.TLSVersion.TLSv1_2

    async def main():
        server = OIXMutualTLSServer(inbox, prekeys, signing_key)
        await server.start(host="127.0.0.1", port=9443, ssl_context=tls)
        try:
            await server.serve_forever()
        finally:
            await server.close()

    asyncio.run(main())

The example deliberately binds to loopback. A non-loopback bind requires the explicit allow_public_bind=True argument. Do not expose a listener to an untrusted network until firewall policy, CA issuance, certificate rotation/revocation, key custody, monitoring, resource limits, and operational incident response have been reviewed.

The receiver's inbox and one-time-prekey store must use the same SQLite database. For each accepted message, decryption, inner-signature validation, inbox policy/replay checks, durable inbox insertion, one-time-prekey consumption, and signed receipt persistence occur in one SQLite transaction.

## Sender requirements

The sender must:
1. Obtain and verify a signed one-time-prekey bundle for the intended OIX recipient.
2. Encrypt and persist the exact secure envelope before attempting delivery.
3. Configure a TLS client context with a client certificate and a CA bundle that validates the receiver's certificate.
4. Call send_encrypted_envelope() with the expected receiver's OIX signing public key and exact logical message ID.
5. On timeout or connection loss, retry the exact same persisted encrypted envelope. Do not create a new envelope or reuse the same logical message ID with different content.

The sender accepts success only after the receipt signature, sender/recipient route, logical message ID, and SHA-256 digest of the exact encrypted wrapper all verify. The receiver persists the receipt before sending it, so a retry after a lost response returns the same durable acknowledgement while it remains valid. Expired acknowledgements are re-issued for the same accepted envelope.

## Framing and limits

- Four-byte unsigned network-order length prefix.
- Canonical JSON object only; duplicate JSON keys and non-canonical encodings are rejected.
- Frame size is bounded by the OIX one-time-prekey envelope limit.
- One encrypted envelope and one signed receipt per TLS connection.
- Read/write timeouts and bounded concurrent handler count.
- Server binds to loopback by default; public binding is explicit opt-in.
- TLS 1.2 minimum; certificate validation is mandatory on both sides.

## Security limitations

- No discovery, rendezvous, relay service, NAT traversal, dynamic endpoint registry, or automatic prekey replenishment.
- No TLS certificate-to-OIX-agent-card binding or automated certificate revocation feed. The CA trust configuration and OIX trusted-peer registry are separate operator-managed controls.
- No rate-limit persistence, IP reputation, DDoS protection, distributed queue, or high-availability failover.
- No encrypted-at-rest SQLite database. Private key storage and database backups remain operator responsibilities.
- A successful TLS handshake authenticates a certificate chain, not the truth of submitted intelligence.
- The receiver never executes received tasks. It only durably records approval-gated work.
- The server intentionally returns no detailed application error to unauthenticated or invalid senders.
- The transport is experimental and has not undergone an independent security audit.

## Test coverage

The transport test suite covers canonical framing, duplicate-key rejection, malformed and truncated frames, oversized frames, TLS certificate validation, loopback-only default binding, encrypted message acceptance, durable signed receipts, and retry behavior after an acknowledgement is lost.
