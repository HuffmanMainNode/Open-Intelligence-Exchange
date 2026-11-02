import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oix.canonical import canonical_json
from oix.envelope import _b64, create_message, verify_for_recipient, verify_message
from oix.evidence import make_evidence
from oix.handshake import negotiate
from oix.identity import generate_identity, load_card, verify_card
from oix.policy import CapabilityPolicy
from oix.replay import ReplayCache


def test_canonical_json_is_stable_and_rejects_float():
    assert canonical_json({"b": 2, "a": "x"}) == b'{"a":"x","b":2}'
    with pytest.raises(TypeError):
        canonical_json({"unsafe": 1.25})


def test_identity_card_signature_and_fingerprint(tmp_path):
    generate_identity(tmp_path, "Test Agent", ["public.research"])
    card = load_card(tmp_path / "agent-card.json")
    assert verify_card(card)
    card["card"]["display_name"] = "tampered"
    assert not verify_card(card)


def test_message_signature_tamper_expiry_and_replay():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    msg = create_message(key, "agent:receiver", "task.request", {"task": "inspect"})
    assert verify_message(msg, public)
    altered = json.loads(json.dumps(msg))
    altered["body"]["payload"]["task"] = "execute"
    assert not verify_message(altered, public)
    assert not verify_message(msg, public, now=msg["body"]["expires_at"] + 1)
    cache = ReplayCache()
    assert cache.accept(msg["body"], now=msg["body"]["issued_at"])
    assert not cache.accept(msg["body"], now=msg["body"]["issued_at"])


def test_wrong_sender_key_rejected():
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    msg = create_message(key, "agent:receiver", "task.request", {})
    assert not verify_message(msg, other)


def test_capability_policy_is_explicit():
    policy = CapabilityPolicy({"public.research"})
    assert policy.permits("public.research")
    assert not policy.permits("filesystem.write")
    assert not policy.permits(None, message_type="task.request")
    assert not policy.permits(None, message_type="evidence.submit")
    assert policy.permits(None, message_type="agent.hello")


def test_evidence_hash_and_status():
    item = make_evidence(
        b"public source content", source_uri="https://example.org/advisory",
        collector_id="test-collector", collector_version="1.0", method="HTTP GET",
    )
    assert len(item["content_sha256"]) == 64
    assert item["evidence_id"] == "sha256:" + item["content_sha256"]
    assert item["status"] == "observed"
    with pytest.raises(ValueError):
        make_evidence(b"x", source_uri="x", collector_id="c", collector_version="1",
                      method="m", status="trusted")



def test_handshake_negotiates_version_and_capabilities():
    card = {"card": {"protocol_version": "0.1", "agent_id": "agent:test",
                     "capabilities": ["public.research", "evidence.review"]}}
    result = negotiate(["0.1"], card, {"evidence.review"})
    assert result["accepted"] is True
    assert result["version"] == "0.1"
    assert result["capabilities"] == ["evidence.review"]
    assert negotiate(["0.2"], card)["accepted"] is False
    denied = negotiate(["0.1"], card, {"filesystem.write"})
    assert denied["reason"] == "missing_capabilities"


def test_identity_generation_refuses_to_overwrite_private_key(tmp_path):
    generate_identity(tmp_path, "First Agent", [])
    original = (tmp_path / "private.key").read_bytes()
    with pytest.raises(FileExistsError):
        generate_identity(tmp_path, "Replacement Agent", [])
    assert (tmp_path / "private.key").read_bytes() == original



@pytest.mark.parametrize("ttl,expected", [(86400, True), (86401, False), (0, False), (-1, False)])
def test_verifier_enforces_ttl_bounds(ttl, expected):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    envelope = create_message(key, "agent:receiver", "task.request", {})
    body = dict(envelope["body"])
    body["expires_at"] = body["issued_at"] + ttl
    envelope["body"] = body
    envelope["signature"] = _b64(key.sign(canonical_json(body)))
    assert verify_message(envelope, public, now=body["issued_at"]) is expected


def test_in_memory_replay_cache_fails_closed_when_full():
    cache = ReplayCache(max_entries=1)
    assert cache.accept({"sender": "a", "nonce": "a" * 24, "expires_at": 200}, now=100)
    assert not cache.accept({"sender": "b", "nonce": "b" * 24, "expires_at": 200}, now=100)
    assert not cache.accept({"sender": "a", "nonce": "a" * 24, "expires_at": 200}, now=100)



def test_verify_for_recipient_binds_message_to_local_agent():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    message = create_message(key, "agent:local", "task.request", {})
    assert verify_for_recipient(message, public, "agent:local")
    assert not verify_for_recipient(message, public, "agent:other")


def test_task_request_requires_explicit_capability():
    policy = CapabilityPolicy({"public.research"})
    assert not policy.permits(None, message_type="task.request")
    assert policy.permits("public.research", message_type="task.request")
    assert not policy.permits("filesystem.write", message_type="task.request")



@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are unavailable")
def test_identity_private_key_is_created_owner_only(tmp_path):
    generate_identity(tmp_path, "Permission Test Agent", [])
    private_key = tmp_path / "private.key"
    assert stat.S_IMODE(private_key.stat().st_mode) == 0o600
