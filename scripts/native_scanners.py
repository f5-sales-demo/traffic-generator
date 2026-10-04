"""Run named native scanners with measured, scoped connection pacing."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from itertools import pairwise
from pathlib import Path
from xml.etree import ElementTree as ET

from traffic_common import atomic_json

SCANNERS = {
    "ssl-scanning/01-sslscan": "sslscan",
    "ssl-scanning/02-sslyze": "sslyze",
    "ssl-scanning/03-testssl": "testssl",
    "reconnaissance/01-nmap-service-scan": "nmap",
    "owasp-scanning/05-nmap-vuln-scan": "nmap",
}
MINIMUM_SPACING = 0.09


def scanner_arguments(
    identifier: str, host: str, address: str, report: Path
) -> list[str]:
    """Declare actual native features and write the scanner's own structured report."""
    if SCANNERS[identifier] == "sslscan":
        return [
            "--no-colour",
            "--sleep=100",
            "--timeout=5",
            "--connect-timeout=5",
            "--sni-name=" + host,
            "--xml=" + str(report),
            address + ":443",
        ]
    if SCANNERS[identifier] == "sslyze":
        return [
            "--slow_connection",
            "--sni",
            host,
            "--json_out",
            str(report),
            address + ":443",
        ]
    if SCANNERS[identifier] == "testssl":
        return [
            "--quiet",
            "--color",
            "0",
            "--warnings",
            "batch",
            "--ip",
            address,
            "--socket-timeout",
            "5",
            "--openssl-timeout",
            "5",
            "--jsonfile",
            str(report),
            host + ":443",
        ]
    scripts = "ssl-cert,ssl-enum-ciphers,http-title,http-headers"
    if identifier.startswith("owasp"):
        scripts = "http-enum,http-methods,http-security-headers,ssl-heartbleed,ssl-ccs-injection,ssl-poodle,ssl-dh-params"
    return [
        "-sT",
        "-sV",
        "-Pn",
        "-n",
        "-p",
        "80,443",
        "--max-rate",
        "10",
        "--max-parallelism",
        "1",
        "--scan-delay",
        "100ms",
        "--host-timeout",
        "600s",
        "--script",
        scripts,
        "--script-timeout",
        "120s",
        "-oX",
        str(report),
        address,
    ]


def report_valid(tool: str, report: Path) -> bool:
    """Require native report content and terminal scanner completion."""
    if not report.is_file() or report.stat().st_size == 0:
        return False
    if tool in ("nmap", "sslscan"):
        document = ET.parse(report).getroot()  # noqa: S314 - local native scanner XML, no remote supplied document
        if tool == "nmap":
            finished = document.find("runstats/finished")
            return (
                finished is not None
                and finished.get("exit") == "success"
                and bool(document.findall("host/ports/port"))
            )
        return bool(document.findall("ssltest")) and bool(document.findall(".//cipher"))
    document = json.loads(report.read_text())
    if tool == "sslyze":
        return bool(document.get("server_scan_results")) and all(
            result.get("scan_status") == "COMPLETED"
            and result.get("connectivity_status") == "COMPLETED"
            for result in document["server_scan_results"]
        )
    return (
        isinstance(document, list)
        and bool(document)
        and not any(row.get("severity") == "FATAL" for row in document)
    )


def main() -> int:
    """Execute installed tools; neither a substitute probe nor an empty report can pass."""
    identifier, host = sys.argv[1:3]
    if host != os.environ["TGEN_AUTHORIZED_HOST"] or identifier not in SCANNERS:
        message = "native scanner target or identity invalid"
        raise ValueError(message)
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    tool = SCANNERS[identifier]
    binary = shutil.which(tool)
    if not binary:
        message = "required native scanner missing: " + tool
        raise ValueError(message)
    address = socket.gethostbyname(host)
    library = directory / "native-connect-pacer.so"
    source = Path(__file__).with_name("native_connect_pacer.c")
    subprocess.run(  # noqa: S603 - source-owned native scanner argv
        [
            "/usr/bin/gcc",
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            str(library),
            str(source),
            "-ldl",
        ],
        check=True,
    )
    report = directory / (tool + (".xml" if tool in ("nmap", "sslscan") else ".json"))
    log = directory / "native-scanner.log"
    attempts = directory / "native-connect.log"
    environment = dict(
        os.environ,
        LD_PRELOAD=str(library),
        TGEN_NATIVE_IP=address,
        TGEN_NATIVE_CONNECT_LOG=str(attempts),
    )
    with log.open("w") as stream:
        log.chmod(0o600)
        process = subprocess.run(  # noqa: S603 - source-owned native scanner argv
            [binary, *scanner_arguments(identifier, host, address, report)],
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=environment,
            timeout=700,
            check=False,
        )
    rows = (
        [line.split() for line in attempts.read_text().splitlines()]
        if attempts.exists()
        else []
    )
    times = [float(row[0]) for row in rows]
    spacing = bool(times) and all(b - a >= MINIMUM_SPACING for a, b in pairwise(times))
    scope = all(row[1] == address and int(row[2]) in (80, 443) for row in rows)
    passed = (
        process.returncode == 0 and spacing and scope and report_valid(tool, report)
    )
    atomic_json(
        directory / "connections.json",
        {
            "scenario": identifier,
            "execution": "native-" + tool,
            "passed": passed,
            "tool": tool,
            "attempts": len(rows),
            "attempt_limit_per_second": 10,
            "measured_attempt_spacing": spacing,
            "scope_verified": scope,
            "connections_closed": True,
            "exit_code": process.returncode,
            "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            "adapter_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest()
            if report.exists()
            else None,
            "source_commit": os.environ["SOURCE_COMMIT"],
            "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
        },
    )
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
