"""Snapshot and restore only a named synthetic RESTaurant actor through native APIs."""

import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

FIELDS = ("username", "phone_number", "first_name", "last_name", "role")


def request(base: str, token: str, body: dict | None = None) -> dict:
    """Use only the configured authorized published RESTaurant route."""
    target = urlsplit(base)
    if (
        target.scheme != "https"
        or target.hostname not in json.loads(os.environ["TGEN_AUTHORIZED_DOMAINS"])
        or target.path != "/restaurant"
        or target.port not in (None, 443)
    ):
        message = "unauthorized fixture route"
        raise ValueError(message)
    req = Request(  # noqa: S310 - exact configured owned HTTPS origin
        base + "/profile",
        data=json.dumps(body).encode() if body is not None else None,
        method="PATCH" if body is not None else "GET",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "X-MUD-User": "benign-" + uuid.uuid4().hex,
        },
    )
    with urlopen(req, timeout=30) as response:  # noqa: S310 - validated HTTPS target
        return json.load(response)


def main() -> int:
    """Journal and restore the seeded actor without creating new users."""
    action, base = sys.argv[1:3]
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    file = directory / "restaurant-role-snapshot.json"
    fixtures = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())
    actor = fixtures["restaurant_attacker"]
    name = actor["username"]
    token = actor["token"]
    if not name.startswith("tgen_bola_"):
        message = "synthetic role actor required"
        raise ValueError(message)
    if action == "snapshot":
        profile = request(base, token)
        if profile.get("username") != name:
            message = "fixture actor mismatch"
            raise ValueError(message)
        file.write_text(json.dumps({field: profile.get(field) for field in FIELDS}))
        file.chmod(0o600)
    elif action == "restore":
        before = json.loads(file.read_text())
        if before["username"] != name:
            message = "snapshot ownership mismatch"
            raise ValueError(message)
        request(
            base,
            token,
            {field: before[field] for field in FIELDS if field != "username"},
        )
        after = request(base, token)
        restored = all(after.get(field) == before[field] for field in FIELDS)
        receipt = directory / "fixture-restoration.json"
        receipt.write_text(
            json.dumps(
                {
                    "restored": restored,
                    "actor": name,
                    "fields": list(FIELDS),
                    "before": before,
                    "after": {field: after.get(field) for field in FIELDS},
                    "source_commit": os.environ.get("SOURCE_COMMIT"),
                    "artifact_sha256": os.environ.get("TGEN_ARTIFACT_SHA256"),
                }
            )
        )
        receipt.chmod(0o600)
        if not restored:
            message = "synthetic role restoration failed"
            raise ValueError(message)
    else:
        message = "unknown fixture action"
        raise ValueError(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
