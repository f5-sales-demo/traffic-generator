#!/usr/bin/env python3
"""Read a real seeded synthetic application token from the private fixture receipt."""

import base64
import json
import os
import sys
import time
from pathlib import Path


def token(kind: str) -> str:
    """Fail closed on missing or unsafe fixture input."""
    path = Path(os.environ["TGEN_FIXTURES"])
    if path.is_symlink() or path.stat().st_mode & 0o077:
        message = "unsafe fixture permissions"
        raise ValueError(message)
    value = json.loads(path.read_text()).get(kind)
    if not isinstance(value, str) or not value:
        message = "required real synthetic fixture token is absent"
        raise ValueError(message)
    encoded = value.split(".")[1] if "." in value else ""
    if encoded:
        payload = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        if payload.get("exp", time.time() + 60) <= time.time():
            message = "real synthetic fixture token expired; refresh required"
            raise ValueError(message)
    return value


if __name__ == "__main__":
    print(token(sys.argv[1] if len(sys.argv) > 1 else "juice_token"))
