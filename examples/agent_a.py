"""Launch an independent receiver process and exchange a signed OIX message."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from oix.envelope import create_message
from oix.handshake import negotiate
from oix.identity import generate_identity, load_card, load_private_key, verify_card


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="oix-demo-") as temp:
        root = Path(temp)
        a_dir, b_dir = root / "agent-a", root / "agent-b"
        generate_identity(a_dir, "Independent Agent A", ["public.research"])
        generate_identity(b_dir, "Independent Agent B", ["evidence.review"])
        a_card = load_card(a_dir / "agent-card.json")
        b_card = load_card(b_dir / "agent-card.json")
        assert verify_card(a_card) and verify_card(b_card)

        agreement = negotiate(["0.1"], b_card, {"evidence.review"})
        if not agreement["accepted"]:
            raise SystemExit(f"handshake rejected: {agreement}")

        envelope = create_message(
            load_private_key(a_dir),
            b_card["card"]["agent_id"],
            "task.request",
            {"objective": "Review this public-source evidence bundle",
             "input_is_untrusted": True},
            capability="evidence.review",
        )
        receiver = Path(__file__).with_name("agent_b.py")
        result = subprocess.run(
            [sys.executable, str(receiver), "--identity", str(b_dir),
             "--sender-card", str(a_dir / "agent-card.json")],
            input=json.dumps(envelope),
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
        receipt = json.loads(result.stdout)
        if receipt.get("accepted") is not True:
            raise SystemExit(f"receiver rejected message: {receipt}")
        print("OIX independent-process exchange: PASS")
        print(f"sender: {a_card['card']['agent_id']}")
        print(f"recipient: {b_card['card']['agent_id']}")
        print("handshake: accepted | signature: valid | replay: guarded")
        print("The receiver treated the payload as data and executed nothing.")


if __name__ == "__main__":
    main()
