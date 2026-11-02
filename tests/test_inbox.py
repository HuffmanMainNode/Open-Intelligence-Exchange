import json
import sqlite3

import pytest

from oix.canonical import canonical_json
from oix.envelope import _b64, create_message
from oix.identity import generate_identity, load_private_key
from oix.inbox import (
    InboxError,
    ReplayError,
    SQLiteInbox,
    UntrustedPeerError,
    WorkStateError,
)
from oix.policy import CapabilityPolicy


def make_agent(tmp_path, name, capabilities):
    directory = tmp_path / name
    card = generate_identity(directory, name, capabilities)
    return load_private_key(directory), card


def test_receive_requires_explicit_trust_and_exact_recipient(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent",
                        CapabilityPolicy({"public.research"}))
    message = create_message(sender_key, "local-agent", "task.request",
                             {"task": "summarize public advisories"},
                             capability="public.research")
    with pytest.raises(UntrustedPeerError):
        inbox.receive(message)
    inbox.trust_peer(sender_card)
    wrong_recipient = create_message(sender_key, "another-agent", "task.request",
                                     {"task": "inspect"}, capability="public.research")
    with pytest.raises(InboxError):
        inbox.receive(wrong_recipient)
    receipt = inbox.receive(message)
    assert receipt.duplicate is False
    assert receipt.work_status == "pending_approval"
    assert inbox.pending_work()[0]["payload"]["task"] == "summarize public advisories"


def test_message_idempotency_and_conflicting_message_id(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent",
                        CapabilityPolicy({"public.research"}))
    inbox.trust_peer(sender_card)
    message = create_message(sender_key, "local-agent", "task.request", {"task": "one"},
                             capability="public.research")
    first = inbox.receive(message)
    second = inbox.receive(message)
    assert first.work_id == second.work_id
    assert second.duplicate is True
    changed = json.loads(json.dumps(message))
    changed["body"]["payload"]["task"] = "tampered"
    with pytest.raises(InboxError):
        inbox.receive(changed)


def test_nonce_replay_with_new_message_id_is_rejected(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent",
                        CapabilityPolicy({"public.research"}))
    inbox.trust_peer(sender_card)
    original = create_message(sender_key, "local-agent", "task.request", {"task": "one"},
                              capability="public.research")
    inbox.receive(original)
    second = create_message(sender_key, "local-agent", "task.request", {"task": "two"},
                            capability="public.research")
    second["body"]["nonce"] = original["body"]["nonce"]
    second["signature"] = _b64(sender_key.sign(canonical_json(second["body"])))
    with pytest.raises(ReplayError):
        inbox.receive(second)


def test_invalid_signature_and_untrusted_key_are_rejected(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent",
                        CapabilityPolicy({"public.research"}))
    inbox.trust_peer(sender_card)
    message = create_message(sender_key, "local-agent", "agent.hello", {})
    message["body"]["payload"]["forged"] = True
    with pytest.raises(InboxError):
        inbox.receive(message)


def test_missing_capability_and_unsupported_shape_are_rejected(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent",
                        CapabilityPolicy({"public.research"}))
    inbox.trust_peer(sender_card)
    no_capability = create_message(sender_key, "local-agent", "task.request", {"task": "x"})
    with pytest.raises(InboxError):
        inbox.receive(no_capability)
    malformed = create_message(sender_key, "local-agent", "agent.hello", {})
    malformed["body"]["unexpected"] = "field"
    with pytest.raises(InboxError):
        inbox.receive(malformed)


def test_expired_message_and_revoked_peer_are_rejected(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", [])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent")
    peer_id = inbox.trust_peer(sender_card)
    expired = create_message(sender_key, "local-agent", "agent.hello", {}, ttl_seconds=10)
    with pytest.raises(InboxError):
        inbox.receive(expired, now=expired["body"]["expires_at"] + 1)
    assert inbox.revoke_peer(peer_id) is True
    valid = create_message(sender_key, "local-agent", "agent.hello", {})
    with pytest.raises(UntrustedPeerError):
        inbox.receive(valid)


def test_operator_decision_is_durable_and_one_way(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    database = tmp_path / "inbox.sqlite3"
    inbox = SQLiteInbox(database, "local-agent", CapabilityPolicy({"public.research"}))
    inbox.trust_peer(sender_card)
    message = create_message(sender_key, "local-agent", "task.request", {"task": "inspect"},
                             capability="public.research")
    receipt = inbox.receive(message)
    assert inbox.decide_work(receipt.work_id, approve=True, decided_at=123) == "approved"
    reopened = SQLiteInbox(database, "local-agent", CapabilityPolicy({"public.research"}))
    assert reopened.pending_work() == []
    with pytest.raises(WorkStateError):
        reopened.decide_work(receipt.work_id, approve=False)


def test_evidence_is_review_gated_and_no_payload_is_executed(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["evidence.submit"])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent",
                        CapabilityPolicy({"evidence.submit"}))
    inbox.trust_peer(sender_card)
    message = create_message(
        sender_key,
        "local-agent",
        "evidence.submit",
        valid_evidence_payload(),
        capability="evidence.submit",
    )
    receipt = inbox.receive(message)
    assert receipt.work_status == "pending_review"
    assert inbox.pending_work()[0]["status"] == "pending_review"
    with sqlite3.connect(inbox.database) as db:
        assert db.execute("SELECT COUNT(*) FROM inbound_work").fetchone()[0] == 1


def test_card_tampering_is_not_trusted(tmp_path):
    _, sender_card = make_agent(tmp_path, "sender", [])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent")
    changed = json.loads(json.dumps(sender_card))
    changed["card"]["capabilities"].append("filesystem.write")
    with pytest.raises(InboxError):
        inbox.trust_peer(changed)


def test_concurrent_duplicate_delivery_creates_one_work_item(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent",
                        CapabilityPolicy({"public.research"}))
    inbox.trust_peer(sender_card)
    message = create_message(sender_key, "local-agent", "task.request", {"task": "inspect"},
                             capability="public.research")
    with ThreadPoolExecutor(max_workers=8) as executor:
        receipts = list(executor.map(lambda _: inbox.receive(message), range(8)))
    assert sum(not receipt.duplicate for receipt in receipts) == 1
    assert len({receipt.work_id for receipt in receipts}) == 1
    assert len(inbox.pending_work()) == 1


def test_inbox_and_work_creation_roll_back_together(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["public.research"])
    database = tmp_path / "inbox.sqlite3"
    inbox = SQLiteInbox(database, "local-agent", CapabilityPolicy({"public.research"}))
    inbox.trust_peer(sender_card)
    with sqlite3.connect(database) as db:
        db.execute(
            """CREATE TRIGGER reject_inbound_work BEFORE INSERT ON inbound_work
               BEGIN SELECT RAISE(ABORT, 'simulated work-store failure'); END"""
        )
    message = create_message(sender_key, "local-agent", "task.request", {"task": "inspect"},
                             capability="public.research")
    with pytest.raises(sqlite3.IntegrityError):
        inbox.receive(message)
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM inbox_messages").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM inbound_work").fetchone()[0] == 0


def valid_evidence_payload():
    return {
        "schema_version": "1.0",
        "evidence_id": "4b3b7a6f-3e5a-4a6d-9f0b-2d9f1c6a7e80",
        "evidence_type": "domain_observation",
        "source_uri": "https://example.org/security-advisory",
        "source_timestamp": None,
        "collected_at": "2026-11-02T00:00:00Z",
        "collector": {"name": "halloween-osint-2026", "version": "0.1.0"},
        "method": {"name": "dns-tls-observation", "version": "1.0"},
        "artifact": {
            "sha256": "a" * 64,
            "size_bytes": 2048,
            "media_type": "application/json",
        },
        "classification": "public",
        "status": "observed",
        "summary": {"record_count": 2, "observation_kind": "domain_infrastructure"},
        "limitations": [
            "The digest identifies the artifact bytes but does not prove source authenticity."
        ],
    }


def test_evidence_submit_requires_strict_metadata_contract_and_operator_review(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "evidence-sender", ["public.research"])
    inbox = SQLiteInbox(
        tmp_path / "inbox.sqlite3",
        "local-agent",
        CapabilityPolicy({"public.research"}),
    )
    inbox.trust_peer(sender_card)
    message = create_message(
        sender_key,
        "local-agent",
        "evidence.submit",
        valid_evidence_payload(),
        capability="public.research",
    )
    receipt = inbox.receive(message)
    assert receipt.work_status == "pending_review"
    work = inbox.pending_work()[0]
    assert work["work_type"] == "evidence.submit"
    assert work["payload"] == valid_evidence_payload()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update({"unexpected": "field"}),
        lambda payload: payload.update({"source_uri": "file:///etc/passwd"}),
        lambda payload: payload["artifact"].update({"sha256": "not-a-digest"}),
        lambda payload: payload.update({"collected_at": "2026-11-02T00:00:00"}),
        lambda payload: payload.update({"schema_version": "2.0"}),
        lambda payload: payload.update({"limitations": []}),
        lambda payload: payload["artifact"].update({"size_bytes": True}),
    ],
)
def test_evidence_submit_rejects_malformed_or_unsafe_payload(tmp_path, mutate):
    sender_key, sender_card = make_agent(tmp_path, "evidence-sender", ["public.research"])
    inbox = SQLiteInbox(
        tmp_path / "inbox.sqlite3",
        "local-agent",
        CapabilityPolicy({"public.research"}),
    )
    inbox.trust_peer(sender_card)
    payload = valid_evidence_payload()
    mutate(payload)
    message = create_message(
        sender_key,
        "local-agent",
        "evidence.submit",
        payload,
        capability="public.research",
    )
    with pytest.raises(InboxError):
        inbox.receive(message)
    assert inbox.pending_work() == []


def test_evidence_payload_validator_rejects_floating_point_summary():
    from oix.inbox import validate_evidence_submit_payload

    payload = valid_evidence_payload()
    payload["summary"]["unsafe_float"] = 1.25
    with pytest.raises(InboxError, match="deterministic JSON"):
        validate_evidence_submit_payload(payload)


def test_get_work_exposes_durable_operator_decision_without_mutating_it(tmp_path):
    sender_key, sender_card = make_agent(tmp_path, "sender", ["evidence.submit"])
    inbox = SQLiteInbox(
        tmp_path / "inbox.sqlite3",
        "local-agent",
        CapabilityPolicy({"evidence.submit"}),
    )
    inbox.trust_peer(sender_card)
    message = create_message(
        sender_key,
        "local-agent",
        "evidence.submit",
        valid_evidence_payload(),
        capability="evidence.submit",
    )
    receipt = inbox.receive(message)

    pending = inbox.get_work(receipt.work_id)
    assert pending["status"] == "pending_review"
    assert pending["sender"] == receipt.sender
    assert pending["message_id"] == receipt.message_id
    assert pending["work_type"] == "evidence.submit"
    assert pending["decided_at"] is None

    assert inbox.decide_work(receipt.work_id, approve=True, decided_at=456) == "approved"
    approved = inbox.get_work(receipt.work_id)
    assert approved["status"] == "approved"
    assert approved["decided_at"] == 456
    assert inbox.get_work(receipt.work_id) == approved


def test_get_work_rejects_unknown_work_id(tmp_path):
    inbox = SQLiteInbox(tmp_path / "inbox.sqlite3", "local-agent")
    with pytest.raises(WorkStateError, match="does not exist"):
        inbox.get_work("missing-work")
