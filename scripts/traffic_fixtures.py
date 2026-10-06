#!/usr/bin/env python3
"""Private seeded-account credentials keep mitigated prerequisites from eliminating launches."""

import fcntl
import json
import os
import sys
from pathlib import Path

MINIMUM_ACCOUNTS = 2


def main() -> int:
    """Return a real origin-issued synthetic token; never fabricate server responses."""
    path = Path(os.environ["TGEN_FIXTURES"])
    if path.is_symlink() or path.stat().st_mode & 0o077:
        message = "unsafe private fixture permissions"
        raise ValueError(message)
    fixtures = json.loads(path.read_text())
    if sys.argv[1] in ("dvwa-session", "dvwa-csrf-session"):
        domain = sys.argv[2]
        sessions = fixtures.get(
            "dvwa_csrf_sessions"
            if sys.argv[1] == "dvwa-csrf-session"
            else "dvwa_sessions",
            {},
        )
        cookie = sessions.get(domain)
        if (
            not isinstance(cookie, str)
            or not cookie
            or "\n" in cookie
            or "\r" in cookie
        ):
            message = "missing real origin-authenticated DVWA fixture"
            raise ValueError(message)
        print("# Netscape HTTP Cookie File")
        print(f"{domain}\tFALSE\t/dvwa/\tFALSE\t0\tPHPSESSID\t{cookie}")
        print(f"{domain}\tFALSE\t/dvwa/\tFALSE\t0\tsecurity\tlow")
        return 0
    if sys.argv[1] != "crapi-token":
        message = "unknown fixture selection"
        raise ValueError(message)
    if fixtures.get("fixture_type") not in (None, "seeded-synthetic-origin-accounts"):
        message = "unsupported fixture identity"
        raise ValueError(message)
    tokens = fixtures["crapi_tokens"]
    if len(tokens) < MINIMUM_ACCOUNTS or any(
        not isinstance(t, str) or not t for t in tokens
    ):
        message = "two real synthetic crAPI account tokens are required"
        raise ValueError(message)
    counter = Path(os.environ["TGEN_RESULTS_DIR"]) / ".crapi-account-index"
    with counter.open("a+") as stream:
        counter.chmod(0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0)
        value = stream.read().strip()
        index = int(value) if value else 0
        stream.seek(0)
        stream.truncate()
        stream.write(str(index + 1))
    print(tokens[index % len(tokens)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
