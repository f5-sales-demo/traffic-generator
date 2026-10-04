"""Native load-tool execution through the shared HTTP pacing boundary."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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
        return [
            binary,
            "-n",
            str(max(level, count)),
            "-c",
            str(level),
            "-s",
            "60",
            *(["-k"] if persistent else []),
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
            *([url] * count if persistent else [url]),
        ]
    message = "undeclared native load tool"
    raise ValueError(message)


def run_worker(tool: str, directory: Path, index: int, args: list[str]) -> dict:
    """Require a completed native report; process exit alone is insufficient."""
    path = directory / (tool + "-" + str(index) + ".log")
    started = time.monotonic()
    with path.open("w") as stream:
        path.chmod(0o600)
        process = subprocess.run(  # noqa: S603 - native argv from source contract
            args, stdout=stream, stderr=subprocess.STDOUT, check=False
        )
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
        "exit_code": process.returncode,
        "elapsed": time.monotonic() - started,
        "passed": process.returncode == 0 and valid,
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
                                run_curl_group(
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
    finally:
        stop.set()
        if profiler.is_alive():
            profiler.join()
    receipt = {
        "scenario": identifier,
        "execution": "native-load-tools",
        "workers": workers,
        "resource_samples": samples,
        "cleanup": True,
        "passed": bool(workers) and all(worker["passed"] for worker in workers),
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
    }
    atomic_json(directory / "native-load.json", receipt)
    return int(not receipt["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
