# OIX signed task-result channel

## Scope

The result channel completes the local request/result lifecycle between OIX and Open-Swarm without introducing a network transport. It is a transport-independent SQLite adapter. It does not open sockets, transmit envelopes, or claim remote delivery.

The Open-Swarm OIX handoff adapter initializes the shared `oix_result_outbox` table. Open-Swarm writes a result record when an OIX-originated task reaches a terminal state. OIX's `SQLiteResultPublisher` provides the operator decision and signing lifecycle.

## Shared database requirement

The request inbox, Open-Swarm task queue, handoff mapping, and result outbox must use the same local SQLite database file. The atomicity guarantee does not extend across separate database files, hosts, network filesystems, or cloud-sync services.

Initialize in this order:

1. Create the OIX `SQLiteInbox` on the shared database.
2. Create the Open-Swarm `TaskQueue` on that same database.
3. Initialize `OIXTaskHandoff(queue)`, which creates the durable handoff and result-outbox tables.
4. Construct `SQLiteResultPublisher(database, local_agent_id, private_key)`.

## Result lifecycle

```text
Open-Swarm terminal task state
        |
        | same SQLite transaction as task completion and audit
        v
pending_approval
        |
        | operator decision
        +---------------------> rejected
        |
        v
approved
        |
        | OIX signs task.result and persists exact envelope
        v
signed
        |
        | separately implemented transport acknowledgement
        v
delivered
```

The result remains `pending_approval` until an operator calls `decide(task_id, approve=True)`. Rejected results cannot be signed. Signing is a distinct step and cannot run before approval.

## API

```python
from oix.result_channel import SQLiteResultPublisher

publisher = SQLiteResultPublisher(
    database=shared_database,
    local_agent_id=local_agent_id,
    private_key=local_private_key,
)

# Inspect records awaiting human review.
for record in publisher.pending():
    print(record["task_id"], record["payload"])

# Explicit operator decision.
publisher.decide(task_id, approve=True)

# Persist one signed envelope. Repeated calls return the same envelope.
envelope = publisher.sign_approved(task_id)

# A future transport may read publisher.pending_delivery(), transmit the
# exact envelope, and call mark_delivered only after authenticated receipt.
for item in publisher.pending_delivery():
    print(item["message_id"], item["envelope"])

# Only call after a real transport confirms delivery to the intended peer.
publisher.mark_delivered(task_id, envelope["body"]["message_id"])
```

The final call above is an interface contract, not a transport implementation. Calling it without a real authenticated delivery acknowledgement would create a false delivery record and must not be done.

## Envelope payload

The signed `task.result` payload contains:

- `task_id`: stable Open-Swarm task identifier
- `request_message_id`: original OIX request message identifier
- `status`: terminal task status (`succeeded`, `failed`, or `blocked`)
- `result`: result text, or null when the result exceeds the bounded release size
- `result_omitted`: true when the result was too large to stage for release

The task prompt and internal execution context are not copied into the result envelope. Error strings are not automatically released. Results larger than 256 KiB are staged with `result_omitted=true`, not silently truncated.

## Durability and retry behavior

- Open-Swarm inserts the result-outbox row in the same transaction as terminal task state and its audit/outbox event.
- Only tasks with a durable `oix_handoffs` mapping receive an OIX result record. Ordinary local tasks do not.
- `task_id` is the result-outbox primary key, preventing duplicate logical result records.
- Operator decisions are one-way from `pending_approval`.
- The signed envelope and its message ID are stored before it is exposed to a transport adapter.
- Repeated signing calls return the persisted envelope rather than creating a new message ID or signature.
- Delivery acknowledgement is bound to the exact persisted message ID and is idempotent.

This is durable local staging, not exactly-once network delivery. A future transport must define authenticated receipts, retry semantics, duplicate handling, recipient-side durable acceptance, and failure recovery.

## Security boundaries

- OIX v0.1 signs messages but does not encrypt payloads. A signature provides integrity and sender-key authentication, not confidentiality or truth.
- Do not approve release of secrets, personal data, restricted investigations, private prompts, credentials, or private search queries.
- Operator review is a release gate, not a content-classification engine. Inspect the complete payload before approval.
- The private signing key must belong to `local_agent_id`; the publisher checks this at initialization.
- The publisher does not fetch peer keys, enroll peers, or deliver messages.
- Shared SQLite storage is single-host. Protect the database and key directory with restrictive OS permissions and encrypted storage appropriate to the classification.
- The current publisher has no multi-operator authorization, quorum, key rotation, encryption, or tamper-evident external audit log.

## Validation boundary

The cross-repository demonstration signs a real OIX `task.request`, receives it through the real `SQLiteInbox`, explicitly approves it, hands it to Open-Swarm, executes the local mock adapter, stages the terminal result, approves the result, signs a `task.result`, and verifies its signature and original recipient. It does not transmit the result or claim remote delivery.


## Encrypted result staging

The Phase 4 publisher can also encrypt an approved signed result for the original peer. `encrypt_approved()` verifies that the peer's X25519 certificate is signed by the Ed25519 identity associated with the original request, then persists the encrypted wrapper and key fingerprint. `pending_secure_delivery()` exposes only these persisted encrypted wrappers. Repeated calls with the same recipient key reuse the stored wrapper. If the peer rotates its encryption key, the same signed result can be re-encrypted without changing its inner message ID.

`pending_delivery()` is plaintext local inspection only. Do not use it as a network transport source. A future transport must use `pending_secure_delivery()` and authenticate the recipient acknowledgement before calling `mark_delivered()`. The publisher adds nullable secure-envelope columns to existing Phase 3 result-outbox databases when initialized.
