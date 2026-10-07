"""Exchange exact blocked-request evidence with the private Ubuntu operator."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from traffic_common import atomic_json

MAX_EVIDENCE_BYTES = 4_000_000


def identity(root: Path) -> dict:
    """Read the installed immutable source identity without credentials."""
    return json.loads((root / "source-receipt.json").read_text())


def pending(root: Path) -> list[dict]:
    """Return requests only from the currently installed source and owned pass paths."""
    expected = identity(root)
    result = []
    for file in (root / "runtime").glob("pass-*/*/control-evidence-request.json"):
        if file.is_symlink() or not file.is_file():
            continue
        request = json.loads(file.read_text())
        if any(
            request.get(key) != expected[key]
            for key in ("source_commit", "artifact_sha256")
        ):
            continue
        if (file.parent / "control-attribution.json").exists():
            continue
        result.append(
            {
                "pass": file.parent.parent.name,
                "request": request,
                "request_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
            }
        )
    return result


def install(root: Path, bundle: dict) -> None:
    """Reject stale source, changed request bytes and any foreign destination."""
    pass_id, scenario = bundle["pass"], bundle["request"]["scenario"]
    if not re.fullmatch(r"pass-[a-f0-9]{32}", pass_id) or not re.fullmatch(
        r"[a-z0-9-]+/[a-z0-9-]+", scenario
    ):
        message = "invalid evidence pass or scenario identity"
        raise ValueError(message)
    directory = root / "runtime" / pass_id / scenario.replace("/", "--")
    if any(parent.is_symlink() for parent in (directory, *directory.parents)):
        message = "evidence path traverses a symbolic link"
        raise ValueError(message)
    request_file = directory / "control-evidence-request.json"
    request = json.loads(request_file.read_text())
    expected = identity(root)
    if (
        request != bundle["request"]
        or hashlib.sha256(request_file.read_bytes()).hexdigest()
        != bundle["request_sha256"]
        or any(
            request.get(key) != expected[key]
            for key in ("source_commit", "artifact_sha256")
        )
    ):
        message = "evidence source or request binding changed"
        raise ValueError(message)
    evidence = bundle["evidence"]
    if any(
        evidence.get(key) != request[key]
        for key in ("source_commit", "artifact_sha256")
    ):
        message = "evidence provenance mismatch"
        raise ValueError(message)
    atomic_json(directory / "control-attribution.json", evidence)


def main() -> None:
    """The transport carries evidence JSON only, never a shell command or API secret."""
    root = Path("/opt/traffic-generator")
    if sys.argv[1:] == ["pending"]:
        print(json.dumps(pending(root)))
        return
    if sys.argv[1:] != ["install"]:
        message = "expected pending or install"
        raise ValueError(message)
    raw = sys.stdin.buffer.read(MAX_EVIDENCE_BYTES + 1)
    if len(raw) > MAX_EVIDENCE_BYTES:
        message = "evidence exceeds bounded input"
        raise ValueError(message)
    install(root, json.loads(raw))


if __name__ == "__main__":
    main()
