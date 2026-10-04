"""Classify native DVWA command output without storing environment values."""

import argparse
import html
import json
import re
from pathlib import Path

HTTP_OK = 200


def main() -> int:
    """Extract the native preformatted output and require the declared application."""
    parser = argparse.ArgumentParser()
    parser.add_argument("body", type=Path)
    parser.add_argument("status", type=int)
    parser.add_argument("pattern")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    body = args.body.read_text(errors="replace")
    output = " ".join(
        html.unescape(value)
        for value in re.findall(r"<pre[^>]*>(.*?)</pre>", body, re.DOTALL | re.IGNORECASE)
    )
    application = (
        args.status == HTTP_OK
        and "DVWA" in body
        and "Logout" in body
        and "Command Injection" in body
    )
    effect = bool(re.search(args.pattern, output, re.IGNORECASE))
    receipt = {
        "application_verified": application,
        "native_output_verified": effect,
        "status": args.status,
        "passed": application and effect,
    }
    with args.output.open("a") as stream:
        args.output.chmod(0o600)
        stream.write(json.dumps(receipt) + "\n")
    return int(not receipt["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
