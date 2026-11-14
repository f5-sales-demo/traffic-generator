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


def operation(
    directory: Path, action: str, family: str, identity: str | None = None
) -> None:
    """Retain ownership before mutation and restore only the host-captured baseline."""
    if family == "mixed":
        bundle_operation(directory, action)
        return
    fixtures = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())
    settings = fixtures["family_recovery"]
    if action not in ("prepare", "restore") or family not in (
        "vampi",
        "dvwa",
        "restaurant",
        "juice-shop",
        "dvga",
        "crapi",
    ):
        message = "invalid declared family action"
        raise ValueError(message)
    journal = directory / "family-journal.json"
    if action == "prepare":
        value = {
            "identity": identity or uuid.uuid4().hex,
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


def bundle_operation(directory: Path, action: str) -> None:
    """Journal all five families with one common marker and exact per-family receipts."""
    identity_file = directory / "family-bundle-identity.json"
    if action == "prepare":
        atomic_json(identity_file, {"identity": uuid.uuid4().hex})
    identity = json.loads(identity_file.read_text())["identity"]
    replicas = {}
    after = {}
    prepared = []
    try:
        for family in ["vampi", "dvwa", "restaurant", "juice-shop", "dvga"]:
            child = directory / "family-bundle" / family
            child.mkdir(mode=0o700, parents=True, exist_ok=True)
            operation(child, action, family, identity)
            prepared.append((child, family))
            receipt = json.loads(
                (
                    child
                    / (
                        "family-baseline.json"
                        if action == "prepare"
                        else "family-restoration.json"
                    )
                ).read_text()
            )
            replicas.update(receipt["replicas"])
            if action == "restore":
                after.update(receipt["after"])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        if action == "prepare":
            for child, family in reversed(prepared):
                operation(child, "restore", family, identity)
        raise
    receipt = {
        "identity": identity,
        "family": "mixed",
        "marker": "tgen-" + identity,
        "replicas": replicas,
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
    }
    if action == "restore":
        receipt.update(restored=True, after=after)
    atomic_json(
        directory
        / (
            "family-baseline.json" if action == "prepare" else "family-restoration.json"
        ),
        receipt,
    )


def recover_pass(root: Path, active: Path | None, config: dict) -> list[dict]:
    """Recover one bounded pass with source ownership and bundle semantics."""
    recovered: list[dict] = []
    bundles = sorted(active.rglob("family-bundle-identity.json")) if active else []
    for identity_file in bundles:
        directory = identity_file.parent
        if (directory / "family-restoration.json").exists():
            continue
        children = sorted((directory / "family-bundle").glob("*/family-journal.json"))
        if not children:
            message = "interrupted family bundle has no owned journals"
            raise ValueError(message)
        for child in children:
            value = json.loads(child.read_text())
            if (
                value.get("source_commit") != config["source_commit"]
                or value.get("artifact_sha256") != config["artifact_sha256"]
            ):
                message = "interrupted family bundle provenance mismatch"
                raise ValueError(message)
        bundle_operation(directory, "restore")
        recovered.append(
            {
                "family": "mixed",
                "identity": json.loads(identity_file.read_text())["identity"],
                "restored": True,
            }
        )
    for journal in sorted(active.rglob("family-journal.json")) if active else []:
        if any(bundle.parent in journal.parents for bundle in bundles):
            continue
        directory = journal.parent
        if journal.is_symlink() or not journal.resolve().is_relative_to(root.resolve()):
            message = "interrupted family journal escaped owned runtime"
            raise ValueError(message)
        value = json.loads(journal.read_text())
        if (
            value.get("source_commit") != config["source_commit"]
            or value.get("artifact_sha256") != config["artifact_sha256"]
        ):
            continue
        if (directory / "family-restoration.json").exists():
            continue
        receipt_path = directory / "receipt.json"
        if (
            receipt_path.exists()
            and json.loads(receipt_path.read_text()).get("outcome") == "fixture_failure"
            and not (directory / "family-baseline.json").exists()
        ):
            continue
        operation(directory, "restore", value["family"])
        recovered.append(
            {
                "family": value["family"],
                "identity": value["identity"],
                "restored": True,
            }
        )
    return recovered


def recover_active(config: dict) -> dict:
    """Restore unfinished journals from the latest source-bound pass before startup."""
    root = Path(config["results_dir"])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or any(parent.is_symlink() for parent in root.parents):
        message = "unsafe interrupted recovery runtime"
        raise ValueError(message)
    passes = sorted(
        (path for path in root.glob("pass-*") if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
    )
    if any(path.is_symlink() for path in passes):
        message = "unsafe interrupted recovery pass"
        raise ValueError(message)
    recovered = []
    environment = {
        "SOURCE_COMMIT": config["source_commit"],
        "TGEN_ARTIFACT_SHA256": config["artifact_sha256"],
    }
    previous = {key: os.environ.get(key) for key in environment}
    os.environ.update(environment)
    try:
        recovered = recover_pass(root, passes[-1] if passes else None, config)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    receipt = {
        "source_commit": config["source_commit"],
        "artifact_sha256": config["artifact_sha256"],
        "recovered": recovered,
    }
    atomic_json(root / "interrupted-family-recovery.json", receipt)
    return receipt


def main() -> None:
    """Called only by the host worker outside the catalog egress namespace."""
    if sys.argv[1] == "recover-active":
        config = json.loads(Path(sys.argv[2]).read_text())
        os.environ["TGEN_FIXTURES"] = str(
            Path(config["results_dir"]).parent / "fixtures.json"
        )
        recover_active(config)
        return
    action, family, destination = sys.argv[1:4]
    operation(Path(destination), action, family)


if __name__ == "__main__":
    main()
