"""Native load-tool execution through the shared HTTP pacing boundary."""

import hashlib
import json
import os
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from native_scanner_process import run_scanner
from stress_reports import report_matches
from traffic_common import atomic_json
from traffic_profile import sample_resources


def command(
    tool: str,
    binary: str,
    url: str,
    level: int,
    count: int,
    duration: int,
    persistent: bool,
) -> list[str]:
    """Use the native tool's real concurrency and connection options."""
    if tool == "hey":
        return [
            binary,
            "-n",
            str(max(level, count)),
            "-c",
            str(level),
            "-t",
            "60",
            *([] if persistent else ["-disable-keepalive"]),
            "-H",
            "Connection: keep-alive" if persistent else "Connection: close",
            url,
        ]
    if tool == "wrk":
        return [
            binary,
            "-t1",
            "-c" + str(level),
            "-d" + str(duration) + "s",
            "--timeout",
            "60s",
            "-H",
            "Connection: keep-alive" if persistent else "Connection: close",
            url,
        ]
    if tool == "ab":
        url = url.replace("https://", "http://", 1)
        return [
            binary,
            "-l",
            "-n",
            str(max(level, count)),
            "-c",
            str(level),
            "-s",
            "60",
            *(["-k"] if persistent else []),
            "-H",
            "Connection: keep-alive" if persistent else "Connection: close",
            url,
        ]
    if tool == "curl":
        return [
            binary,
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "60",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code} %{num_connects}\n",
            "-H",
            "Connection: keep-alive" if persistent else "Connection: close",
            *(
                [
                    argument
                    for _ in range(count)
                    for argument in ("--output", "/dev/null", url)
                ]
                if persistent
                else [url]
            ),
        ]
    message = "undeclared native load tool"
    raise ValueError(message)


def run_worker(tool: str, directory: Path, index: int, args: list[str]) -> dict:
    """Require a completed native report; process exit alone is insufficient."""
    path = directory / (tool + "-" + str(index) + ".log")
    started = time.monotonic()
    process = run_scanner(args, dict(os.environ), path, 600)
    text = path.read_text()
    valid = (
        report_matches(tool, text)
        if tool != "curl"
        else bool(text.strip())
        and all(line.split()[0] == "200" for line in text.splitlines())
    )
    return {
        "tool": tool,
        "report": path.name,
        "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "exit_code": process["exit_code"],
        "process_evidence": process,
        "elapsed": time.monotonic() - started,
        "passed": process["exit_code"] == 0
        and not process["timed_out"]
        and process["connections_closed"]
        and valid,
    }


def run_vegeta(
    binary: str, url: str, duration: int, persistent: bool, directory: Path, index: int
) -> dict:
    """Run actual Vegeta attack and encode its real per-request response records."""
    attack = directory / ("vegeta-" + str(index) + ".raw")
    encoded = directory / ("vegeta-" + str(index) + ".bin")
    arguments = [
        binary,
        "attack",
        "-workers=1",
        "-max-workers=2",
        "-rate=5/s",
        "-duration=" + str(duration) + "s",
        "-timeout=60s",
        "-keepalive=" + str(persistent).lower(),
    ]
    target = (
        "GET "
        + url
        + "\nConnection: "
        + ("keep-alive" if persistent else "close")
        + "\n"
    ).encode()
    # Vegeta writes a binary report to stdout; retain stderr separately without mixing bytes.
    native_log = directory / ("vegeta-" + str(index) + ".log")
    process = run_scanner(
        arguments,
        dict(os.environ),
        attack,
        duration + 120,
        target,
        native_log,
    )
    report = run_scanner(
        [binary, "encode"],
        dict(os.environ),
        encoded,
        60,
        attack.read_bytes(),
    )
    return {
        "tool": "vegeta",
        "report": encoded.name,
        "report_sha256": hashlib.sha256(encoded.read_bytes()).hexdigest(),
        "passed": process["exit_code"] == 0
        and not process["timed_out"]
        and process["connections_closed"]
        and report["exit_code"] == 0
        and report["connections_closed"]
        and report_matches("vegeta", encoded.read_text()),
        "exit_code": process["exit_code"],
        "process_evidence": process,
        "encode_process_evidence": report,
        "attack_cleanup_basis": "native attack process reaped; encode process group observed absent",
    }


def run_curl_group(
    binary: str,
    url: str,
    level: int,
    count: int,
    persistent: bool,
    directory: Path,
    offset: int,
) -> list[dict]:
    """Native curl processes perform actual parallel requests or connection reuse."""

    def worker(index: int) -> dict:
        args = command(
            "curl", binary, url, 1, count if persistent else 1, 1, persistent
        )
        return run_worker("curl", directory, offset + index, args)

    with ThreadPoolExecutor(max_workers=level) as pool:
        return list(pool.map(worker, range(level if persistent else count)))


def run_lua(
    binary: str, host: str, contract: dict, directory: Path, index: int
) -> dict:
    """Execute the checked-in native wrk Lua script and retain its digest."""
    script = Path(__file__).resolve().parents[1] / contract["lua_script"]
    if not script.is_file():
        message = "required native wrk Lua phase missing"
        raise ValueError(message)
    args = [
        binary,
        "-t1",
        "-c2",
        "-d" + str(contract["duration_seconds"]) + "s",
        "--timeout",
        "60s",
        "-s",
        str(script),
        "https://" + host + "/",
    ]
    worker = run_worker("wrk", directory, index, args)
    worker.update(
        lua_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
    )
    return worker


def main() -> int:
    """Run each source-declared native level/path without replacement request engines."""
    identifier, host = sys.argv[1:3]
    if host != os.environ["TGEN_AUTHORIZED_HOST"]:
        message = "unauthorized native load target"
        raise ValueError(message)
    scenario = next(
        item
        for item in json.loads(
            (Path(__file__).resolve().parents[1] / "suites/catalog.json").read_text()
        )["scenarios"]
        if item["id"] == identifier
    )
    contract = scenario["native_load_contract"]
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    workers: list[dict] = []
    samples = []
    stop = threading.Event()

    def monitor() -> None:
        while not stop.wait(0.5):
            samples.append(sample_resources())

    profiler = threading.Thread(target=monitor, daemon=True)
    if contract.get("resource_profile"):
        profiler.start()
    try:
        for tool in contract["tools"]:
            binary = shutil.which(tool)
            if binary is None:
                message = "native load tool missing: " + tool
                raise ValueError(message)
            for level in contract["levels"]:
                for count in contract["batches"]:
                    for persistent in contract["connection_modes"]:
                        for path in contract["paths"]:
                            group = (
                                [
                                    run_vegeta(
                                        binary,
                                        "https://" + host + path,
                                        contract["duration_seconds"],
                                        persistent,
                                        directory,
                                        len(workers),
                                    )
                                ]
                                if tool == "vegeta"
                                else run_curl_group(
                                    binary,
                                    "https://" + host + path,
                                    level,
                                    count,
                                    persistent,
                                    directory,
                                    len(workers),
                                )
                                if tool == "curl"
                                else [
                                    run_worker(
                                        tool,
                                        directory,
                                        len(workers),
                                        command(
                                            tool,
                                            binary,
                                            "https://" + host + path,
                                            level,
                                            count,
                                            contract["duration_seconds"],
                                            persistent,
                                        ),
                                    )
                                ]
                            )
                            for worker in group:
                                worker.update(
                                    path=path,
                                    concurrency=level,
                                    persistent=persistent,
                                    binary_sha256=hashlib.sha256(
                                        Path(binary).read_bytes()
                                    ).hexdigest(),
                                )
                            workers.extend(group)
            if tool == "wrk" and contract.get("lua_script"):
                workers.append(run_lua(binary, host, contract, directory, len(workers)))
    finally:
        stop.set()
        if profiler.is_alive():
            profiler.join()
    receipt = {
        "scenario": identifier,
        "execution": "native-load-tools",
        "workers": workers,
        "resource_samples": samples,
        "cleanup": bool(workers)
        and all(
            worker.get("process_evidence", {}).get("connections_closed") is True
            for worker in workers
        ),
        "passed": bool(workers) and all(worker["passed"] for worker in workers),
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
    }
    atomic_json(directory / "native-load.json", receipt)
    return int(not receipt["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
