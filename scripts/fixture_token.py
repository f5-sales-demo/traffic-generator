#!/usr/bin/env python3
"""Read a real seeded synthetic application token from the private fixture receipt."""

import base64
import json
import os
import sys
import time
from pathlib import Path


def restaurant_actors(fixtures: dict) -> tuple[dict, dict]:
    """Reject a self-modification masquerading as a cross-account BOLA action."""
    actors = tuple(
        fixtures.get("restaurant_" + role, {}) for role in ("attacker", "victim")
    )
    if any(
        not isinstance(actor, dict)
        or not isinstance(actor.get("username"), str)
        or not actor["username"].startswith("tgen_bola_")
        or not isinstance(actor.get("token"), str)
        or not actor["token"]
        for actor in actors
    ):
        message = "required synthetic BOLA actor fixture absent"
        raise ValueError(message)
    if (
        actors[0]["username"] == actors[1]["username"]
        or actors[0]["token"] == actors[1]["token"]
    ):
        message = "BOLA requires distinct synthetic actor identities and tokens"
        raise ValueError(message)

    for actor in actors:
        try:
            encoded = actor["token"].split(".")[1]
            payload = json.loads(
                base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            )
            expires = payload["exp"]
        except (ValueError, IndexError, KeyError, TypeError) as error:
            message = "BOLA actor issued token invalid"
            raise ValueError(message) from error
        if payload.get("sub") != actor["username"]:
            message = "BOLA actor token identity mismatch"
            raise ValueError(message)
        if not isinstance(expires, (int, float)) or expires <= time.time():
            message = "BOLA actor token expired; refresh required"
            raise ValueError(message)
    return actors[0], actors[1]


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
    if len(sys.argv) > 1 and sys.argv[1] == "restaurant-actors":
        path = Path(os.environ["TGEN_FIXTURES"])
        if path.is_symlink() or path.stat().st_mode & 0o077:
            message = "unsafe fixture permissions"
            raise ValueError(message)
        print(json.dumps(restaurant_actors(json.loads(path.read_text()))))
    else:
        print(token(sys.argv[1] if len(sys.argv) > 1 else "juice_token"))
