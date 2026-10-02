#!/usr/bin/env python3
"""One verified immutable catalog installer for Azure cloud-init and live updates."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen


def install(commit: str, digest: str, destination: Path) -> None:
    """Verify archive bytes before promoting a task-owned source installation."""
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(
        r"[a-f0-9]{64}", digest
    ):
        message = "exact source commit and artifact SHA-256 required"
        raise ValueError(message)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=destination) as temporary:
        staging = Path(temporary)
        archive = staging / "source.tar.gz"
        with urlopen(
            "https://codeload.github.com/f5-sales-demo/traffic-generator/tar.gz/"
            + commit,
            timeout=60,
        ) as response:
            payload = response.read(50 * 1024**2 + 1)
        if len(payload) > 50 * 1024**2 or hashlib.sha256(payload).hexdigest() != digest:
            message = "generator artifact digest or size mismatch"
            raise ValueError(message)
        archive.write_bytes(payload)
        with tarfile.open(archive) as tar_source:
            tar_source.extractall(staging, filter="data")
        source = staging / ("traffic-generator-" + commit)
        subprocess.run(  # noqa: S603 - validated content-addressed source
            [
                shutil.which("python3") or "/usr/bin/python3",
                str(source / "scripts/traffic_catalog.py"),
                "catalog",
                "--dry-run",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        installed = destination / ("source-" + commit)
        if installed.exists():
            shutil.rmtree(installed)
        source.rename(installed)
        link = destination / (".current-" + str(os.getpid()))
        link.symlink_to(installed.name)
        link.replace(destination / "current")
        receipt = {
            "source_commit": commit,
            "artifact_sha256": digest,
            "source": str(installed),
        }
        path = destination / "source-receipt.json"
        path.write_text(json.dumps(receipt))
        path.chmod(0o600)


def main() -> None:
    """Install a verified catalog artifact."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--destination", type=Path, default=Path("/opt/traffic-generator")
    )
    args = parser.parse_args()
    install(args.commit, args.sha256, args.destination)


if __name__ == "__main__":
    main()
