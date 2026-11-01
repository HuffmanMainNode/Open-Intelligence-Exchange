"""Run two independent local agents through the OIX signed-envelope path."""
from __future__ import annotations

import tempfile
from pathlib import Path

from oix.envelope import create_message, verify_message
from oix.identity import generate_identity, load_private_key, load_card, verify_card
from oix.policy import CapabilityPolicy
from oix.replay import ReplayCache


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="oix-demo-") as temp:
        root = Path(temp)
        generate_identity(root / "agent-a", "Independent Research Agent A", ["public.research"])
        generate_identity(root / "agent-b", "Independent Review Agent B", ["evidence.review"])
        a_card = load_card(root / "agent-a" / "agent-card.json")
        b_card = load_card(root / "agent-b" / "agent-card.json")
        assert verify_card(a_card) and verify_card(b_card)

        message = create_message(
            load_private_key(root / "agent-a"),
            b_card["card"]["agent_id"],
            "task.request",
            {"objective": "Review this public-source evidence bundle", "input_is_untrusted": True},
            capability="evidence.review",
        )

        receiver_public = __import__("base64").urlsafe_b64decode(
            a_card["card"]["public_key"] + "=" * (-len(a_card["card"]["public_key"]) % 4)
        )
        assert verify_message(message, receiver_public)
        assert message["body"]["recipient"] == b_card["card"]["agent_id"]

        replay = ReplayCache()
        assert replay.accept(message["body"])
        assert not replay.accept(message["body"])

        policy = CapabilityPolicy({"evidence.review"})
        assert policy.permits(message["body"]["requested_capability"])
        print("OIX exchange: PASS")
        print(f"sender: {a_card['card']['agent_id']}")
        print(f"recipient: {b_card['card']['agent_id']}")
        print("signature: valid | replay: blocked | capability: allowed")
        print("No received content was executed.")


if __name__ == "__main__":
    main()
