"""Receiver process: read one envelope from stdin, verify, authorize, emit receipt."""
from __future__ import annotations

import argparse
import base64
import json
import sys

from oix.envelope import verify_message
from oix.handshake import negotiate
from oix.identity import load_card, verify_card
from oix.policy import CapabilityPolicy
from oix.replay import ReplayCache


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True)
    parser.add_argument("--sender-card", required=True)
    args = parser.parse_args()

    own = load_card(f"{args.identity}/agent-card.json")
    sender = load_card(args.sender_card)
    envelope = json.load(sys.stdin)
    if not verify_card(own) or not verify_card(sender):
        raise SystemExit("invalid identity card")
    sender_public = base64.urlsafe_b64decode(
        sender["card"]["public_key"] + "=" * (-len(sender["card"]["public_key"]) % 4)
    )
    body = envelope.get("body", {})
    if not verify_message(envelope, sender_public):
        raise SystemExit("invalid message signature or validity window")
    if body.get("sender") != sender["card"]["agent_id"]:
        raise SystemExit("sender identity mismatch")
    if body.get("recipient") != own["card"]["agent_id"]:
        raise SystemExit("message addressed to another agent")
    agreement = negotiate(["0.1"], sender, set())
    if not agreement["accepted"]:
        raise SystemExit("protocol negotiation failed")
    policy = CapabilityPolicy(set(own["card"]["capabilities"]))
    if not policy.permits(body.get("requested_capability")):
        raise SystemExit("requested capability denied")
    replay = ReplayCache()
    if not replay.accept(body):
        raise SystemExit("replayed or expired message")
    print(json.dumps({
        "accepted": True,
        "message_id": body["message_id"],
        "sender": body["sender"],
        "capability": body.get("requested_capability"),
        "payload_received": True,
        "payload_executed": False,
    }))


if __name__ == "__main__":
    main()
