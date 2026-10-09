"""Native passive Subfinder discovery; never scan discovered hosts."""

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from native_scanner_process import run_scanner
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
    report = directory / "subfinder-native.jsonl"
    errors = directory / "subfinder-native.log"
    process = run_scanner(
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
        dict(os.environ),
        report,
        90,
        stderr_path=errors,
    )
    rows = [
        json.loads(line) for line in report.read_text().splitlines() if line.strip()
    ]
    passed = (
        process["exit_code"] == 0
        and process["timed_out"] is False
        and process["connections_closed"] is True
        and process["remaining_after_cleanup"] == []
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
            "authorized_domain": domain,
            "process": process,
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
