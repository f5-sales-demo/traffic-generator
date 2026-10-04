"""Native passive Subfinder discovery; never scan discovered hosts."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from traffic_common import atomic_json


def main() -> int:
    """Retain native discovery output and provider errors without invented names."""
    identifier, host = sys.argv[1:3]
    if host != os.environ["TGEN_AUTHORIZED_HOST"]:
        message = "unauthorized passive discovery target"
        raise ValueError(message)
    domain = ".".join(host.split(".")[-2:])
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    binary = shutil.which("subfinder")
    if binary is None:
        message = "native Subfinder missing"
        raise ValueError(message)
    result = subprocess.run(  # noqa: S603 - scoped native passive discovery
        [
            binary,
            "-d",
            domain,
            "-silent",
            "-json",
            "-rl",
            "5",
            "-timeout",
            "15",
            "-max-time",
            "1",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    report = directory / "subfinder-native.jsonl"
    report.write_text(result.stdout)
    report.chmod(0o600)
    errors = directory / "subfinder-native.log"
    errors.write_text(result.stderr)
    errors.chmod(0o600)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    passed = (
        result.returncode == 0
        and bool(rows)
        and all(
            row.get("host", "").endswith("." + domain) and row.get("source")
            for row in rows
        )
    )
    atomic_json(
        directory / "native-discovery.json",
        {
            "scenario": identifier,
            "execution": "native-subfinder",
            "passed": passed,
            "discoveries": len(rows),
            "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            "source_commit": os.environ["SOURCE_COMMIT"],
            "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
            "claim": "passive discovery on authorized root; discovered names never scanned",
        },
    )
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
