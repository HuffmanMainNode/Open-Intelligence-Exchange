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
    message = create_message(sender_key, "local-agent", "evidence.submit",
                             {"source_uri": "https://example.org", "claim": "unverified"},
                             capability="evidence.submit")
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
