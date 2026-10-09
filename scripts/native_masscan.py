"""Native Masscan with exact authorized ports and packet-level pacing evidence."""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

PORTS = {80, 443}
MINIMUM_SPACING = 0.99


def main() -> int:
    """Run the installed scanner and fail if any intended SYN lacks its real reply."""
    identifier, host = sys.argv[1:3]
    if host != os.environ.get("TGEN_AUTHORIZED_HOST"):
        message = "unauthorized native scanner target"
        raise ValueError(message)
    address = str(
        socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    )
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    binary = shutil.which("masscan")
    if binary is None:
        message = "native Masscan missing"
        raise ValueError(message)
    report = directory / "masscan-native.json"
    log = directory / "masscan-native.log"
    command = [
        binary,
        address,
        "-p80,443",
        "--rate",
        "1",
        "--retries",
        "0",
        "--wait",
        "5",
        "--packet-trace",
        "-oJ",
        str(report),
    ]
    with log.open("w") as stream:
        log.chmod(0o600)
        process = subprocess.run(  # noqa: S603 - exact authorized scanner argv
            command, stdout=stream, stderr=subprocess.STDOUT, timeout=60, check=False
        )
    text = log.read_text()
    sent = re.findall(
        r"SENT \(([0-9.]+)\) TCP  \[[^]]+\]:[0-9]+ +> \[([^]]+)\]:([0-9]+) +SYN\s*$",
        text,
        re.MULTILINE,
    )
    replies = re.findall(
        r"RCVD \([0-9.]+\) TCP  \[([^]]+)\]:([0-9]+) +> .* SYN-ACK", text
    )
    offered = {int(port) for _, ip, port in sent if ip == address}
    received = {int(port) for ip, port in replies if ip == address}
    times = sorted(float(attempt) for attempt, _, _ in sent)
    spacing = len(times) == len(PORTS) and times[-1] - times[0] >= MINIMUM_SPACING
    passed = (
        process.returncode == 0
        and len(sent) == len(PORTS)
        and offered == PORTS
        and received == PORTS
        and spacing
    )
    receipt = {
        "scenario": identifier,
        "execution": "native-masscan",
        "passed": passed,
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "native_report_sha256": hashlib.sha256(report.read_bytes()).hexdigest()
        if report.exists()
        else None,
        "attempts": len(sent),
        "attempt_limit_per_second": 1,
        "maximum_slow_connections": 0,
        "connections_closed": True,
        "intended_ports": sorted(PORTS),
        "offered_ports": sorted(offered),
        "responding_ports": sorted(received),
        "measured_attempt_spacing": spacing,
        "source_commit": os.environ.get("SOURCE_COMMIT"),
        "artifact_sha256": os.environ.get("TGEN_ARTIFACT_SHA256"),
    }
    (directory / "connections.json").write_text(json.dumps(receipt))
    (directory / "connections.json").chmod(0o600)
    if report.exists():
        report.chmod(0o600)
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
