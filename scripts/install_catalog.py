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
                "-B",
                str(source / "scripts/traffic_catalog.py"),
                "catalog",
                "--dry-run",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        installed = destination / ("source-" + commit)
        if installed.exists():
            # Reuse only an exact inventory; extra scripts invalidate immutable provenance.
            expected = {
                str(p.relative_to(source)) for p in source.rglob("*") if p.is_file()
            }
            actual = {
                str(p.relative_to(installed))
                for p in installed.rglob("*")
                if p.is_file()
            }
            if expected != actual or any(p.is_symlink() for p in installed.rglob("*")):
                message = (
                    "existing immutable source inventory differs from verified artifact"
                )
                raise ValueError(message)
            for candidate in source.rglob("*"):
                if candidate.is_file():
                    existing = installed / candidate.relative_to(source)
                    if (
                        not existing.is_file()
                        or hashlib.sha256(existing.read_bytes()).digest()
                        != hashlib.sha256(candidate.read_bytes()).digest()
                    ):
                        message = (
                            "existing immutable source differs from verified artifact"
                        )
                        raise ValueError(message)
        else:
            source.rename(installed)
        for candidate in installed.rglob("*"):
            if candidate.is_dir():
                candidate.chmod(0o555)
            elif candidate.is_file():
                candidate.chmod(0o555 if candidate.stat().st_mode & 0o111 else 0o444)
        installed.chmod(0o555)
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


def install_service(destination: Path, system_root: Path = Path("/")) -> None:
    """Install the verified artifact's supervised control without enabling traffic."""
    source = destination / "current/scripts"
    control = system_root / "usr/local/bin/tgen-control"
    service = system_root / "etc/systemd/system/tgen-continuous.service"
    control.parent.mkdir(parents=True, exist_ok=True)
    service.parent.mkdir(parents=True, exist_ok=True)
    if system_root == Path("/"):
        subprocess.run(  # noqa: S603 - installed verified catalog dependency adapter
            ["/usr/bin/python3", str(source / "install_native_wrk.py")],
            check=True,
        )
    control.write_text(
        (source / "tgen-control")
        .read_text()
        .replace("/opt/traffic-generator", str(destination))
    )
    control.chmod(0o755)
    service.write_text(
        (source / "tgen-continuous.service")
        .read_text()
        .replace("/opt/traffic-generator", str(destination))
    )
    service.chmod(0o644)
    if system_root == Path("/"):
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)


def main() -> None:
    """Install a verified catalog artifact."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--destination", type=Path, default=Path("/opt/traffic-generator")
    )
    parser.add_argument("--install-service", action="store_true")
    args = parser.parse_args()
    install(args.commit, args.sha256, args.destination)
    if args.install_service:
        install_service(args.destination)


if __name__ == "__main__":
    main()
