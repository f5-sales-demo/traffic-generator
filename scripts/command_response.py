"""Classify native DVWA command output without storing environment values."""

import argparse
import hashlib
import html
import json
import re
from pathlib import Path

HTTP_OK = 200
HTTP_FORBIDDEN = 403


def main() -> int:
    """Extract the native preformatted output and require the declared application."""
    parser = argparse.ArgumentParser()
    parser.add_argument("body", type=Path)
    parser.add_argument("status", type=int)
    parser.add_argument("pattern")
    parser.add_argument("output", type=Path)
    parser.add_argument("--identity")
    args = parser.parse_args()
    body = args.body.read_text(errors="replace")
    output = " ".join(
        html.unescape(value)
        for value in re.findall(
            r"<pre[^>]*>(.*?)</pre>", body, re.DOTALL | re.IGNORECASE
        )
    )
    application = (
        args.status == HTTP_OK
        and "DVWA" in body
        and "Logout" in body
        and "Command Injection" in body
    )
    effect = (
        "4 packets transmitted, 4 received" in output and "uid=" not in output
        if args.pattern == "negative-backtick-no-stdout"
        else bool(re.search(args.pattern, output, re.IGNORECASE))
    )
    receipt = {
        "application_verified": application,
        "native_output_verified": effect,
        "expected_negative": args.pattern == "negative-backtick-no-stdout",
        "status": args.status,
        "passed": application and effect,
        "mitigation_candidate": args.status == HTTP_FORBIDDEN,
        "synthetic_identity": args.identity,
        "response_sha256": hashlib.sha256(args.body.read_bytes()).hexdigest(),
    }
    with args.output.open("a") as stream:
        args.output.chmod(0o600)
        stream.write(json.dumps(receipt) + "\n")
    return int(not receipt["passed"] and not receipt["mitigation_candidate"])


if __name__ == "__main__":
    raise SystemExit(main())
