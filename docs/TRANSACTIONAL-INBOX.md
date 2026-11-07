# Transactional OIX inbox and trust boundary

**Status:** Phase 2 reference implementation. Local SQLite only. No network listener is enabled.

## Acceptance sequence

1. Parse a bounded OIX v0.1 envelope with an exact field allow-list.
2. Resolve the sender only from the receiver's local trusted-peer table.
3. Re-verify the stored signed agent card and its public-key fingerprint.
4. Verify message signature, sender fingerprint, exact recipient, timestamp window, TTL, message type, and UUID.
5. Apply the receiver's local capability allow-list. Task and evidence messages without an explicit capability are denied.
6. Begin an SQLite IMMEDIATE transaction, reject duplicate sender/nonce pairs, and persist the accepted inbox record.
7. For task.request and evidence.submit, create the corresponding work item in the same transaction. Tasks begin as pending_approval; evidence begins as pending_review.
8. Commit before returning an acceptance receipt.

A duplicate message ID with identical canonical content returns the original receipt. Reuse of a message ID with different content is a conflict. Reuse of a nonce with a different message ID is rejected. The database uniqueness constraints are the final concurrency guard.

## Trust administration

Peers are not trusted merely because a signed card arrives with a message. An operator must explicitly call trust_peer(signed_card). The card signature and key fingerprint are verified before storage. revoke_peer(agent_id) removes local trust; previously received records remain available for audit.

A valid signature proves possession of a key, not the identity, honesty, or competence of its operator. Trust is local to this inbox database and is not synchronized by discovery.

## Approval and execution boundary

The inbox never executes payloads, starts workers, invokes tools, opens URLs, or grants filesystem/network access. Task requests are held for operator approval. Evidence submissions are held for review. decide_work records a one-way local decision only; it does not dispatch a task or establish that evidence is true.

An Open-Swarm adapter must consume approved work through a separately reviewed integration. For crash-safe task submission, the inbox and Open-Swarm task/outbox rows must share one SQLite transaction and a stable unique remote-message key. A two-database sequence of marking a nonce then submitting a task is not acceptable because a crash can lose work.

## Confidentiality

OIX v0.1 signs messages but does not encrypt them. This inbox is not an encryption layer. Do not send private prompts, case details, secrets, personal data, restricted intelligence, or internal search queries over OIX transport. Keep any network listener disabled until authenticated transport, confidentiality/key custody, rate limits, timeouts, and key rotation/revocation procedures are reviewed.

## Storage and operations

The database is local SQLite with WAL and a 5-second default busy timeout. POSIX database files are created/restricted to mode 0600; Windows requires host-level access controls. Back up the database securely. Do not place it in a public repository or shared untrusted directory.

The inbox is a single-host persistence component, not a distributed broker. Multi-host replay and trust synchronization are not implemented.


## Read-only decision lookup

`SQLiteInbox.get_work(work_id)` returns the durable inbound work record, including sender, message ID, message type, payload, status, creation time and operator decision timestamp. It is a read-only lookup intended for downstream integrations that must verify that a particular message was explicitly approved. It does not change the decision, execute the payload, or dispatch work. Unknown work IDs raise `WorkStateError`.


## Peer revocation and outstanding work

Revoking a trusted peer removes its local trust record and terminally changes that peer's not-yet-dispatched inbound work from pending approval, pending review, or approved to revoked. The original message remains in the inbox for audit. Re-trusting the same key does not reactivate old work; a new message and a new operator decision are required.

Work already marked dispatched is not canceled by this local inbox operation. Downstream runtimes must enforce their own cancellation and revocation policy for work that has crossed the dispatch boundary. This is a local SQLite lifecycle guarantee, not a federated revocation propagation protocol.


## Result outbox revocation

When the shared OIX result outbox table is present, peer revocation also changes that peer's undelivered pending-approval, approved, and signed result records to rejected in the same SQLite transaction. The rejection reason is recorded as recipient peer revoked. A previously signed or encrypted result is no longer returned by pending-delivery queries, and re-trusting the peer does not restore it. Results already marked delivered remain historical delivery records.

This is a local integration contract with the Open-Swarm result outbox. It does not retract a result already transmitted over a network, and it does not cancel an already-dispatched task.
