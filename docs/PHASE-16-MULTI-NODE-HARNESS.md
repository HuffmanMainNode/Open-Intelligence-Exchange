# Phase 16: Independent multi-node interoperability harness

**Status:** Experimental local multi-process demonstration. This phase proves an initial independent-node exchange path; it is not a production federation deployment.

## Objective

Demonstrate that independently configured OIX installations can exchange a signed discovery batch over the existing Phase 15 mutual-TLS discovery transport without sharing identity keys, application databases, or local discovery state.

## Reproducible demonstration

Run:

```bash
python examples/multi_node_discovery_demo.py
```

The harness creates:
- Two independent Ed25519 OIX agent identities.
- Two independent OS processes.
- Two distinct SQLite discovery databases and state directories.
- Separate TLS leaf certificates carrying each node's OIX agent URI SAN.
- A temporary test CA used as an explicitly configured trust root.
- An explicit receiver-side relay allow-list containing only Node A.
- A signed, expiring discovery announcement and bounded exchange batch.

Node A stores its own local announcement, then sends the batch to Node B. Node B validates the mutual-TLS peer identity and relay allow-list, independently verifies the signed announcement and card, stores the subject as `discovered_untrusted`, and returns an acknowledgement bound to the exact batch UUID and canonical SHA-256 digest. The sender verifies that acknowledgement.

The integration test `tests/test_multi_node_discovery.py` runs this harness as a child process. CI runs the test across Python 3.11, 3.12, and 3.13.

## Acceptance checks

- [x] Two separate operating-system processes.
- [x] Distinct Ed25519 identities.
- [x] Separate SQLite databases.
- [x] Mutual TLS and OIX URI SAN identity binding.
- [x] Explicit receiver-side approved-relay allow-list.
- [x] Independently verified signed announcement and agent card.
- [x] Acknowledgement bound to exact batch ID and digest.
- [x] Discovery subject remains `discovered_untrusted`.
- [x] Advertised endpoint is not fetched, resolved, probed, or contacted.
- [x] Reproducible integration test added to CI.
- [ ] Three-or-more-node forwarding demonstration.
- [ ] Independent hosts or network namespaces.
- [ ] WAN deployment, NAT traversal, or rendezvous.
- [ ] Distributed replay coordination or consensus.
- [ ] External security review.

## Security and operational boundaries

The temporary CA and certificates are generated only for this local test. They are not a production PKI, enrollment authority, or certificate-revocation system. The nodes share a test CA trust root but do not share application identity keys or databases. The receiver's allow-list is explicit and local.

The test uses loopback networking. It does not prove internet reachability, NAT traversal, public relay safety, availability, or performance under hostile network load. Discovery remains separate from trust and authorization. A valid signature proves control of a key, not the truth of an intelligence claim. No received payload is executed.

The Phase 15 transport and Phase 12-14 discovery/exchange/gossip primitives are reused. This phase adds a multi-process interoperability harness and CI regression, not a second transport or discovery protocol.

## Next maturity gates

1. Add a third independently configured node and explicitly demonstrate bounded forwarding while preserving the original batch ID and digest.
2. Add negative tests for unapproved relay certificates, wrong expected peer identity, malformed and oversized batches, expired announcements, duplicate sequence numbers, and unavailable peers.
3. Exercise restart and recovery with the receiver database preserved across process restarts.
4. Add isolated network namespaces or independent CI services before claiming multi-host behavior.
5. Design distributed replay coordination only after its threat model and consistency requirements are explicit.
