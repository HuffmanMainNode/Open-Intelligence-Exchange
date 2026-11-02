# Durable inbox decision lookup

`SQLiteInbox.get_work(work_id)` returns a read-only snapshot of one inbound work item:

- work ID
- sender fingerprint
- original OIX message ID
- message type and requested capability
- validated message payload
- current work status
- creation timestamp
- operator decision timestamp, when decided

## Intended use

A downstream local integration may use this method to confirm that a particular `evidence.submit` or `task.request` has reached an operator-approved state before it performs its own separate ingestion or dispatch step.

`get_work` does not mutate the item. It does not approve, reject, execute, or dispatch the payload. `decide_work` remains the explicit operator decision method. Unknown IDs raise `WorkStateError`.

## Example

```python
receipt = inbox.receive(envelope)
# Present receipt.work_id and its payload to an operator.
# Do not ingest or dispatch while status is pending_review/pending_approval.

decision = inbox.decide_work(receipt.work_id, approve=True)
if decision == "approved":
    work = inbox.get_work(receipt.work_id)
    if work["status"] == "approved":
        # A downstream integration may now verify exact sender/message/payload.
        pass
```

## Trust boundary

A local database status is an auditable local state transition, not a cryptographically signed approval receipt. Integrations must use the same protected inbox database and verify the exact sender, message ID, message type and payload they intend to process. A work approval is not blanket authorization for unrelated side effects.
