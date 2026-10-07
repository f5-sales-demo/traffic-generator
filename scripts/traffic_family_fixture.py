"""Exchange fixed native family journal operations over a restricted SSH key."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

from traffic_common import atomic_json


def operation(directory: Path, action: str, family: str) -> None:
    """Retain ownership before mutation and restore only the host-captured baseline."""
    fixtures = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())
    settings = fixtures["family_recovery"]
    if action not in ("prepare", "restore") or family not in (
        "vampi",
        "dvwa",
        "restaurant",
    ):
        message = "invalid declared family action"
        raise ValueError(message)
    journal = directory / "family-journal.json"
    if action == "prepare":
        value = {
            "identity": uuid.uuid4().hex,
            "family": family,
            "source_commit": os.environ["SOURCE_COMMIT"],
            "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
        }
        atomic_json(journal, value)
    else:
        value = json.loads(journal.read_text())
    for key in ("key", "known_hosts"):
        file = Path(settings[key])
        if file.is_symlink() or file.stat().st_mode & 0o077:
            message = "unsafe family recovery credential"
            raise ValueError(message)
    if not re.fullmatch(r"[0-9.]+", settings["host"]):
        message = "invalid owned family recovery destination"
        raise ValueError(message)
    request = {
        "identity": value["identity"],
        "family": family,
        "action": "snapshot" if action == "prepare" else "restore",
    }
    result = subprocess.run(  # noqa: S603 - fixed forced SSH recovery with structured journal
        [
            "/usr/bin/ssh",
            "-i",
            settings["key"],
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + settings["known_hosts"],
            "root@" + settings["host"],
            "recover-family",
        ],
        input=json.dumps(request).encode(),
        capture_output=True,
        check=True,
        timeout=90,
    )
    receipt = json.loads(result.stdout)
    if receipt.get("identity") != value["identity"] or (
        action == "restore" and receipt.get("restored") is not True
    ):
        message = "native family restoration identity mismatch"
        raise ValueError(message)
    atomic_json(
        directory
        / (
            "family-baseline.json" if action == "prepare" else "family-restoration.json"
        ),
        {
            **receipt,
            "source_commit": value["source_commit"],
            "artifact_sha256": value["artifact_sha256"],
        },
    )


def main() -> None:
    """Called only by the host worker outside the catalog egress namespace."""
    action, family, destination = sys.argv[1:4]
    operation(Path(destination), action, family)


if __name__ == "__main__":
    main()
