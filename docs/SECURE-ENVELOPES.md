# OIX authenticated encrypted envelopes

## Purpose

OIX v0.1 message envelopes are Ed25519-signed but not encrypted. The secure-envelope module adds a transport-independent confidentiality wrapper around an already-signed OIX message. It does not change the inner v0.1 message contract, open sockets, perform peer discovery, or deliver messages.

The wrapper uses:

- X25519 ephemeral-sender to static-recipient key agreement;
- HKDF-SHA256 for key derivation;
- ChaCha20-Poly1305 for authenticated encryption;
- the recipient's Ed25519-signed X25519 key certificate to bind the encryption key to a trusted OIX identity;
- the original inner Ed25519 message signature for sender authentication and message integrity.

## Key setup

Generate an ordinary OIX Ed25519 identity first. Then create a separate X25519 encryption key and signed public-key certificate:

```python
from oix.identity import generate_identity, load_private_key
from oix.secure_transport import generate_encryption_key, load_encryption_private_key

signed_card = generate_identity("./agent", "Agent", ["public.research"])
signing_key = load_private_key("./agent")
certificate = generate_encryption_key("./agent", signing_key)
encryption_key = load_encryption_private_key("./agent")
```

Files:
- `private.key`: Ed25519 signing private key, owner-only POSIX mode `0600`
- `agent-card.json`: signed Ed25519 identity card
- `encryption.key`: X25519 private key, owner-only POSIX mode `0600`
- `encryption-certificate.json`: Ed25519-signed X25519 public-key certificate

The certificate binds the X25519 public key to the agent ID derived from the Ed25519 public key. Certificates are time-bounded and may be valid for no more than 30 days. The caller must distribute the certificate through an authenticated channel and verify it against the recipient's trusted Ed25519 public key.

## Encrypt and decrypt

```python
from oix.envelope import create_message
from oix.secure_transport import encrypt_envelope, decrypt_envelope

# Sender signs the ordinary OIX message first.
signed_message = create_message(
    sender_signing_private_key,
    recipient_agent_id,
    "task.request",
    {"task": "summarize public advisories"},
    capability="public.research",
)

# Sender encrypts to a certificate verified against its trusted peer card.
secure_message = encrypt_envelope(
    signed_message,
    recipient_encryption_certificate,
    recipient_trusted_ed25519_public_key,
)

# Recipient decrypts and verifies the inner signature, sender, and exact recipient.
signed_message = decrypt_envelope(
    secure_message,
    recipient_x25519_private_key,
    recipient_own_encryption_certificate,
    recipient_own_ed25519_public_key,
    sender_trusted_ed25519_public_key,
    recipient_agent_id,
)

# Pass the recovered signed message to the normal durable OIX inbox.
receipt = inbox.receive(signed_message)
```

The encrypted wrapper contains only authenticated routing metadata, a fresh ephemeral X25519 public key, a 96-bit AEAD nonce, and ciphertext. The inner OIX message remains signed and is checked after decryption. The authenticated header is supplied as AEAD associated data, so changes to the sender, recipient, key fingerprint, ephemeral key, nonce, or issue time invalidate decryption.

## Security properties and boundaries

- **Confidentiality in transit:** observers without the recipient's X25519 private key cannot decrypt the wrapped message.
- **Integrity:** ChaCha20-Poly1305 authenticates ciphertext and outer routing metadata.
- **Sender authentication:** the decrypted inner OIX envelope must verify against the sender's trusted Ed25519 key and exact local recipient.
- **Recipient binding:** encryption requires a valid certificate for the exact recipient named in the inner OIX message.
- **Certificate binding:** the recipient's Ed25519 key signs the X25519 certificate. A certificate signed by a different identity is rejected.
- **Replay:** decryption does not replace OIX inbox replay protection. Pass decrypted messages into `SQLiteInbox.receive()` or another durable replay-aware receiver.
- **Size bounds:** inner messages remain bounded by the OIX 1 MB limit; secure envelopes are bounded at 1.1 MB.

## Important limitations

1. **No forward secrecy against recipient-key compromise.** The sender uses a fresh ephemeral X25519 key, but the recipient uses a long-lived static X25519 key. If that recipient private key is later compromised, previously captured ciphertexts encrypted to it may be decrypted. A future prekey or authenticated ephemeral key agreement protocol is required for forward secrecy.
2. **Key rotation and revocation are not automated.** Operators must distribute updated signed certificates, retain old private keys for messages addressed to still-valid old certificates, and revoke compromised keys through a separately defined trust update.
3. **Private keys are not encrypted at rest.** Protect identity directories with restrictive OS permissions and encrypted storage. Do not commit or sync private keys to public repositories.
4. **No transport is implemented.** This module only wraps and unwraps data. It does not listen, connect, route, retry, acknowledge delivery, or expose a public endpoint.
5. **No automatic inbox integration.** The caller must decrypt, then pass the inner signed message to the normal OIX inbox for trust, policy, expiry, nonce, and durable replay checks.
6. **No hidden-reasoning exchange.** Encryption does not change the OIX rule that messages should carry authorized task inputs, status, evidence, and outputs, not private chain-of-thought.

Do not expose a network listener until key custody, rotation/revocation, forward secrecy, replay behavior, denial-of-service limits, authenticated receipts, and deployment threat models have been independently reviewed.

## Validation

`tests/test_secure_transport.py` covers a full signed-message round trip, ciphertext/header tampering, wrong recipient, wrong sender key, invalid certificates, certificate expiry, delayed decryption after certificate expiry, key-file permissions, and overwrite protection. GitHub Actions runs the suite on Python 3.11, 3.12, and 3.13.


## Encrypted outbound task results

`SQLiteResultPublisher.encrypt_approved()` can wrap an already-signed, operator-approved `task.result` for the original requesting peer. It verifies that the recipient X25519 certificate is signed by the Ed25519 identity bound to the original request sender, then persists the encrypted wrapper and recipient key fingerprint. `pending_secure_delivery()` exposes only persisted encrypted wrappers. Repeated calls using the same recipient key reuse the exact stored wrapper. The original signed message ID remains unchanged if the same result is re-encrypted after a peer key rotation.

Use `pending_delivery()` only for local plaintext inspection. Future network transports must consume `pending_secure_delivery()` and authenticate a recipient acknowledgement before recording delivery.


## Peer encryption-key lifecycle

`SQLitePeerKeyStore` stores peer X25519 certificates separately from the Ed25519 trust card. Initial installation requires a valid certificate signed by the already-trusted Ed25519 identity. Replacing an active encryption key requires an explicit local `approve_rotation=True` decision and a certificate with a strictly newer `issued_at` value. Superseded and revoked key generations cannot be reactivated. Revocation invalidates every stored generation for that peer and is retained in the local event history.

This is an operator-controlled local registry, not an online key directory or automatic key-update protocol. It does not distribute certificates, prove that a peer still controls a key, or provide forward secrecy. The current encryption construction still uses a static recipient X25519 key.

## Signed durable-delivery receipts

A transport receiver should issue a receipt only after the exact encrypted wrapper has been durably accepted into its local inbox. The receipt is a normal Ed25519-signed OIX `delivery.receipt` message. Its payload binds the original logical message ID to the SHA-256 digest of the exact encrypted wrapper and states `durable=true`.

The sender verifies:
- the receipt signature against the original recipient's trusted Ed25519 key;
- the expected recipient-to-sender route;
- the exact signed result message ID;
- the digest of the exact persisted encrypted wrapper;
- the durable-acceptance status and receipt validity window.

`SQLiteResultPublisher.mark_delivered()` now requires this verified receipt and persists the receipt alongside the delivery state. A bare transport callback, matching message ID, or unsigned acknowledgement cannot mark a result delivered. The receipt proves the peer identity signed an assertion of durable acceptance; it is not independent proof of storage hardware, continued availability, or human review.

No network transport is implemented in this phase.


For callers that want the local key lifecycle policy enforced at encryption time, use `SQLitePeerKeyStore.encrypt_for_peer()` instead of passing a certificate directly to the low-level `encrypt_envelope()` primitive. The store selects only the currently active, non-expired certificate for the exact trusted recipient identity and refuses encryption after local revocation.


## One-time prekeys

Phase 6 adds an optional one-time-prekey exchange for callers that need stronger protection against later compromise of the recipient's long-term X25519 key.

The receiver creates a signed bundle of one-time X25519 public keys. The corresponding private keys remain in its local owner-only SQLite store. A sender verifies the bundle against the recipient's trusted Ed25519 identity, chooses one unused prekey, and encrypts an already-signed OIX message using a fresh ephemeral X25519 key, HKDF-SHA256, and ChaCha20-Poly1305.

On receipt, `SQLitePreKeyStore.consume_and_decrypt()` takes a SQLite write lock, loads the exact private prekey, authenticates and decrypts the wrapper, verifies the inner OIX signature and recipient, and deletes the private prekey before committing. Invalid ciphertext does not consume the key. Concurrent duplicate deliveries serialize; only one can successfully consume a given prekey.

Example:

```python
from oix.prekeys import (
    SQLitePreKeyStore,
    create_prekey_bundle,
    encrypt_prekey_envelope,
)

# Recipient side: keep this store private and local.
prekeys = SQLitePreKeyStore("./agent/prekeys.sqlite3")
public_bundle = create_prekey_bundle(prekeys, recipient_signing_private_key)

# Sender side: verify the bundle against the trusted recipient signing key.
encrypted = encrypt_prekey_envelope(
    signed_message,
    public_bundle,
    recipient_trusted_ed25519_public_key,
)

# Recipient side: successful decryption consumes the one-time private key.
opened = prekeys.consume_and_decrypt(
    encrypted,
    recipient_signing_public_key,
    sender_trusted_ed25519_public_key,
    local_agent_id,
)
```

### Forward-secrecy boundaries

The one-time-prekey path avoids reusing a static recipient X25519 private key for every message. Its forward-secrecy benefit depends on the recipient's one-time private key being securely erased after use and not recoverable from backups, filesystem snapshots, database copies, or storage-device remnants. SQLite secure-delete is enabled and the database uses rollback-journal mode, but software cannot guarantee physical erasure on all SSDs, filesystems, virtualized disks, or backup systems.

Prekey bundles are signed and time-bounded, but this phase does not provide an online prekey directory, automatic replenishment, remote prekey reservation, or network transport. Bundle distribution must occur over an authenticated channel. A bundle may be replayed, but each corresponding private key can be consumed only once locally. Operators should publish replenishment bundles before the available pool runs low.

The existing static-recipient secure-envelope API remains available for compatibility. Callers must explicitly choose the one-time-prekey API to obtain these properties.
