"""Deterministic bounded load qualifications sharing the namespace HTTP pacing budget."""

import hashlib
import http.client
import json
import os
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from traffic_common import atomic_json


def content_identity(path: str, content_type: str, body: bytes) -> bool:
    """Require declared application content and type rather than an arbitrary 200."""
    root = Path(__file__).resolve().parents[1]
    applications = json.loads((root / "suites/applications.json").read_text())[
        "applications"
    ]
    page = next(
        (
            page
            for app in applications
            for page in app["pages"]
            if app["prefix"] + page["path"] == path
        ),
        None,
    )
    if page is None:
        return False
    return (
        content_type.split(";", 1)[0] == page["content_type"]
        and page["identity"].casefold()
        in body.decode("utf-8", errors="replace").casefold()
    )


def run_level(
    domain: str, paths: list[str], concurrency: int, requests: int, keepalive: bool
) -> dict:
    """Measure actual worker concurrency, connection reuse, latency and response content."""
    local = threading.local()
    connections = []
    lock = threading.Lock()
    active = 0
    maximum_active = 0

    def request(index: int) -> dict:
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        started = time.monotonic()
        result: dict[str, Any] = {
            "path": paths[index % len(paths)],
            "transport_failure": False,
            "content_valid": False,
        }
        if not keepalive or not hasattr(local, "connection"):
            local.connection = http.client.HTTPSConnection(
                domain, timeout=15, context=ssl.create_default_context()
            )
            with lock:
                connections.append(local.connection)
        try:
            local.connection.request(
                "GET",
                result["path"],
                headers={"Connection": "keep-alive" if keepalive else "close"},
            )
            response = local.connection.getresponse()
            body = response.read()
            result.update(
                status=response.status,
                content_type=response.getheader("Content-Type"),
                body_sha256=hashlib.sha256(body).hexdigest(),
                content_valid=content_identity(
                    result["path"], response.getheader("Content-Type", ""), body
                ),
            )
        except (OSError, http.client.HTTPException):
            result["transport_failure"] = True
            local.connection.close()
            del local.connection
        finally:
            if not keepalive and hasattr(local, "connection"):
                local.connection.close()
            with lock:
                active -= 1
        result["elapsed"] = time.monotonic() - started
        return result

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(request, range(requests)))
    for connection in connections:
        connection.close()
    return {
        "concurrency": concurrency,
        "maximum_active": maximum_active,
        "requests": len(results),
        "transport_failures": sum(result["transport_failure"] for result in results),
        "content_failures": sum(not result["content_valid"] for result in results),
        "elapsed": time.monotonic() - started,
        "connections_created": len(connections),
        "persistent": keepalive,
        "connections_closed": all(
            connection.sock is None for connection in connections
        ),
        "results": results,
    }


def main() -> int:
    """Run manifest-owned workload levels and retain a private measurable receipt."""
    root = Path(__file__).resolve().parents[1]
    identifier, domain = sys.argv[1:3]
    if domain != os.environ["TGEN_AUTHORIZED_HOST"]:
        message = "unauthorized workload target"
        raise ValueError(message)
    catalog = json.loads((root / "suites/catalog.json").read_text())
    scenario = next(item for item in catalog["scenarios"] if item["id"] == identifier)
    contract = scenario["workload_contract"]
    started = time.monotonic()
    samples = [
        run_level(
            domain,
            contract["paths"],
            level,
            contract["minimum_requests"],
            "churn" not in identifier and "ephemeral" not in identifier,
        )
        for level in contract["levels"]
    ]
    if "sustained" in identifier or "profile" in identifier:
        while time.monotonic() - started < int(os.environ["TGEN_DURATION"]):
            samples.append(
                run_level(
                    domain,
                    contract["paths"],
                    contract["levels"][-1],
                    contract["minimum_requests"],
                    True,
                )
            )
    receipt = {
        "scenario": identifier,
        "levels": samples,
        "cleanup": all(sample["connections_closed"] for sample in samples),
        "elapsed": time.monotonic() - started,
    }
    atomic_json(Path(os.environ["TGEN_RESULTS_DIR"]) / "workload.json", receipt)
    return int(
        any(
            sample["transport_failures"] or sample["content_failures"]
            for sample in samples
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
