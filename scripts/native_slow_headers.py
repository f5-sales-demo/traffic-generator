"""Native OpenSSL slow-header probes with bounded clients and actual writes."""

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import IO, cast

from traffic_common import Pacer, atomic_json

MAX_CONNECTIONS = 20
ROUNDS = 3


def main() -> int:
    """Open actual OpenSSL TLS clients and send incomplete HTTP headers."""
    identifier, host = sys.argv[1:3]
    if host != os.environ["TGEN_AUTHORIZED_HOST"]:
        message = "unauthorized native slow-header target"
        raise ValueError(message)
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    binary = shutil.which("openssl")
    if binary is None:
        message = "native OpenSSL missing"
        raise ValueError(message)
    address = socket.gethostbyname(host)
    count = min(MAX_CONNECTIONS, int(os.environ["TGEN_SLOW_CONNECTIONS"]))
    rate = min(MAX_CONNECTIONS, int(os.environ["TGEN_CONNECTION_RATE"]))
    pacer = Pacer(rate)
    workers = []
    results: list[dict] = []
    started = time.monotonic()
    try:
        for index in range(count):
            log = (directory / ("openssl-" + str(index) + ".log")).open("wb")
            attempted = pacer.acquire()
            process = subprocess.Popen(  # noqa: S603 - native scoped TLS client
                # pylint: disable=consider-using-with
                [
                    binary,
                    "s_client",
                    "-connect",
                    address + ":443",
                    "-servername",
                    host,
                    "-quiet",
                    "-state",
                    "-ign_eof",
                ],
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=log,
            )
            log.close()
            workers.append(process)
            cast("IO[bytes]", process.stdin).write(
                ("GET / HTTP/1.1\r\nHost: " + host + "\r\n").encode()
            )
            cast("IO[bytes]", process.stdin).flush()
            results.append(
                {
                    "port": 443,
                    "connected": True,
                    "partial_headers_sent": True,
                    "attempted_monotonic": attempted,
                    "write_events": [],
                }
            )
        for round_index in range(ROUNDS):
            time.sleep(5)
            for process, result in zip(workers, results, strict=True):
                try:
                    cast("IO[bytes]", process.stdin).write(
                        b"X-Native-Slow: bounded\r\n"
                    )
                    cast("IO[bytes]", process.stdin).flush()
                    result["write_events"].append({"round": round_index, "sent": True})
                except BrokenPipeError:
                    result["write_events"].append(
                        {
                            "round": round_index,
                            "sent": False,
                            "error_type": "BrokenPipeError",
                        }
                    )
    finally:
        for process in workers:
            cast("IO[bytes]", process.stdin).close()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    for index, result in enumerate(results):
        text = (directory / ("openssl-" + str(index) + ".log")).read_text(
            errors="replace"
        )
        result["connected"] = "SSL negotiation finished successfully" in text
    receipt = {
        "scenario": identifier,
        "execution": "native-openssl-slow-headers",
        "attempts": len(results),
        "attempt_limit_per_second": rate,
        "maximum_slow_connections": len(workers),
        "results": results,
        "elapsed_seconds": time.monotonic() - started,
        "slow_header_writes": sum(
            event["sent"] for result in results for event in result["write_events"]
        ),
        "connections_closed": all(process.poll() is not None for process in workers),
    }
    atomic_json(directory / "connections.json", receipt)
    return int(not results or not all(result["connected"] for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
