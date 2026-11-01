"""Command-line interface for local OIX workflows."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .envelope import create_message, verify_message, write_message
from .identity import generate_identity, load_card, load_private_key, verify_card


def _json_object(value: str) -> dict:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("payload must be a JSON object")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(prog="oix", description="Open Intelligence Exchange tools")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate a local Ed25519 agent identity")
    keygen.add_argument("--out", required=True)
    keygen.add_argument("--name", default="OIX Agent")
    keygen.add_argument("--capability", action="append", default=[])

    card = sub.add_parser("card", help="verify and display a signed agent card")
    card.add_argument("--identity", required=True)

    sign = sub.add_parser("sign", help="create and sign a message envelope")
    sign.add_argument("--identity", required=True)
    sign.add_argument("--to", required=True)
    sign.add_argument("--type", required=True)
    sign.add_argument("--capability")
    sign.add_argument("--payload", required=True, type=_json_object)
    sign.add_argument("--out", required=True)

    verify = sub.add_parser("verify", help="verify a message signature and time window")
    verify.add_argument("message")
    verify.add_argument("--public-key", required=True, help="signed agent-card JSON")

    args = parser.parse_args()
    if args.command == "keygen":
        signed = generate_identity(args.out, args.name, args.capability)
        print(json.dumps(signed["card"], indent=2))
    elif args.command == "card":
        signed = load_card(Path(args.identity) / "agent-card.json")
        if not verify_card(signed):
            raise SystemExit("INVALID: agent card signature or fingerprint")
        print(json.dumps(signed["card"], indent=2))
    elif args.command == "sign":
        envelope = create_message(
            load_private_key(args.identity), args.to, args.type, args.payload,
            capability=args.capability,
        )
        write_message(envelope, args.out)
        print(f"Signed message written to {args.out}")
    elif args.command == "verify":
        envelope = json.loads(Path(args.message).read_text(encoding="utf-8"))
        card_data = load_card(args.public_key)
        if not verify_card(card_data):
            raise SystemExit("INVALID: sender agent card")
        import base64
        public_raw = base64.urlsafe_b64decode(
            card_data["card"]["public_key"] + "=" * (-len(card_data["card"]["public_key"]) % 4)
        )
        ok = verify_message(envelope, public_raw)
        if not ok or envelope["body"]["sender"] != card_data["card"]["agent_id"]:
            raise SystemExit("INVALID: message signature, sender, or validity window")
        print("VALID: signature and validity window verified")


if __name__ == "__main__":
    main()
