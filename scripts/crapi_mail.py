"""Decode exact-recipient native crAPI welcome and password-reset MailHog messages."""

import json
import re
import sys
from email import policy
from email.parser import Parser
from email.utils import getaddresses


def decode_message(item: dict) -> str:
    """Decode native MIME parts instead of matching arbitrary four-digit strings."""
    message = Parser(policy=policy.default).parsestr(item["Raw"]["Data"])
    parts = message.walk() if message.is_multipart() else [message]
    return "\n".join(
        part.get_content()
        for part in parts
        if part.get_content_type() in ("text/plain", "text/html")
    )


def owned_messages(document: dict, recipient: str) -> list[dict]:
    """Recipient equality is required; substring matches cannot identify a fixture."""
    return [
        item
        for item in document.get("items", [])
        if recipient.casefold()
        in {
            address.casefold()
            for _, address in getaddresses(
                item.get("Content", {}).get("Headers", {}).get("To", [])
            )
        }
    ]


def extract(document: dict, recipient: str, kind: str) -> dict:
    """Require the native reset subject and labeled OTP, or welcome vehicle VIN."""
    matches = []
    for item in owned_messages(document, recipient):
        subject = item.get("Content", {}).get("Headers", {}).get("Subject", [])
        body = decode_message(item)
        pattern = (
            r"Your one time generated otp is:\s*(\d{4})(?!\d)"
            if kind == "otp"
            else r"VIN:[\s\S]*?>([A-HJ-NPR-Z0-9]{17})<"
        )
        if kind == "otp" and subject != ["crAPI OTP"]:
            continue
        found = re.search(pattern, body)
        if found:
            matches.append({"message_id": item["ID"], "value": found[1]})
    if len(matches) != 1:
        message = "exact native crAPI mail missing or ambiguous"
        raise ValueError(message)
    return matches[0]


def main() -> int:
    """Read actual MailHog JSON from curl; emit only a verified native value."""
    kind, recipient = sys.argv[1:3]
    if kind not in ("otp", "welcome"):
        message = "unknown crAPI mail workflow"
        raise ValueError(message)
    print(extract(json.load(sys.stdin), recipient, kind)["value"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
