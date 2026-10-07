"""Run preserved native scenario commands between source-bound family journal jobs."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from traffic_common import atomic_json


def host_action(directory: Path, action: str, family: str) -> None:
    """Wait for the owning host to snapshot or restore; never grant direct host access."""
    request = {
        "action": action,
        "family": family,
        "identity": uuid.uuid4().hex,
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
    }
    response = directory / "family-host-response.json"
    response.unlink(missing_ok=True)
    atomic_json(directory / "family-host-request.json", request)
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        if response.exists():
            receipt = json.loads(response.read_text())
            if receipt.get("request") != request or receipt.get("passed") is not True:
                message = "native family host job failed"
                raise ValueError(message)
            return
        time.sleep(0.5)
    message = "family journal host deadline exceeded"
    raise ValueError(message)


def main() -> int:
    """Serialize each shared family while leaving all preserved attack payloads intact."""
    identifier, domain = sys.argv[1:3]
    root = Path(__file__).resolve().parents[1]
    scenario = next(
        row
        for row in json.loads((root / "suites/catalog.json").read_text())["scenarios"]
        if row["id"] == identifier
    )
    family = scenario["fixture_contract"]["family_restore"]
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    families = (
        ["dvga", "dvwa", "juice-shop", "restaurant", "vampi"]
        if family == "mixed"
        else [family]
    )
    with contextlib.ExitStack() as stack:
        for selected in families:
            lock_path = Path(os.environ["TGEN_FIXTURES"]).parent / (
                selected + "-catalog-mutation.lock"
            )
            lock = stack.enter_context(lock_path.open("a"))
            lock_path.chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
        host_action(directory, "prepare", family)
        try:
            result = subprocess.run(  # noqa: S603 - checked catalog native entrypoint and target
                [
                    ("node" if scenario["kind"] == "javascript" else "/usr/bin/bash"),
                    str(root / scenario["entrypoint"]),
                    domain,
                ],
                check=False,
                env={
                    **os.environ,
                    "TGEN_FAMILY_MARKER": json.loads(
                        (directory / "family-baseline.json").read_text()
                    )["marker"],
                },
            )
            return result.returncode
        finally:
            host_action(directory, "restore", family)


if __name__ == "__main__":
    raise SystemExit(main())
