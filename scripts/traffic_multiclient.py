"""Complete correlated synthetic client identity requests without deadline cancellation."""

import http.client
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from native_http import request
from traffic_common import atomic_json
from traffic_workload import content_identity

HTTP_OK = 200
APPLICATIONS = json.loads(
    (Path(__file__).resolve().parents[1] / "suites/applications.json").read_text()
)["applications"]
APPLICATION_PATHS = tuple(app["prefix"] + app["benign_path"] for app in APPLICATIONS)


def identity_matches(headers: dict, address: str, marker: str) -> bool:
    """Verify the forwarded headers and client cookie on this specific response."""
    normalized = {key.lower(): value for key, value in headers.items()}
    return (
        normalized.get("true-client-ip") == address
        and normalized.get("fastly-client-ip") == address
        and normalized.get("cookie") == "tgen_client=" + marker
    )


def client(domain: str, index: int) -> dict:
    """One independent client repeats its own synthetic identity five times."""
    address = "192.0.2." + str(index + 1)
    marker = "client-" + str(index)
    checks = []
    try:
        for _ in range(5):
            check: dict[str, Any] = {"passed": False}
            try:
                status, _, response_body = request(
                    "https://" + domain + "/httpbin/headers",
                    headers={
                        "X-Forwarded-For": address,
                        "True-Client-IP": address,
                        "CF-Connecting-IP": address,
                        "Fastly-Client-IP": address,
                        "Cookie": "tgen_client=" + marker,
                    },
                )
                body = json.loads(response_body)
                check["passed"] = status == HTTP_OK and identity_matches(
                    body.get("headers", {}), address, marker
                )
                check["status"] = status
            except (OSError, ValueError, http.client.HTTPException):
                check["error"] = "client identity or transport failed"
            checks.append(check)
        application_checks = []
        for application_path in APPLICATION_PATHS:
            item = {"path": application_path, "passed": False}
            try:
                status, response_headers, body = request(
                    "https://" + domain + application_path,
                    headers={
                        "Cookie": "tgen_client=" + marker,
                        "True-Client-IP": address,
                        "Fastly-Client-IP": address,
                    },
                )
                item["passed"] = status == HTTP_OK and content_identity(
                    application_path, response_headers.get("content-type", ""), body
                )
            except (OSError, ValueError, http.client.HTTPException):
                item["error"] = "client application or transport failed"
            application_checks.append(item)
    finally:
        pass
    return {
        "client": marker,
        "checks": checks,
        "application_checks": application_checks,
        "connections_closed": True,
        "passed": all(check["passed"] for check in [*checks, *application_checks]),
    }


def main() -> int:
    """Run twenty independent clients under the shared namespace pacing clock."""
    identifier, domain = sys.argv[1:3]
    if domain != os.environ["TGEN_AUTHORIZED_HOST"]:
        message = "unauthorized multi-client target"
        raise ValueError(message)
    with ThreadPoolExecutor(max_workers=20) as pool:
        clients = list(pool.map(lambda index: client(domain, index), range(20)))
    receipt = {
        "scenario": identifier,
        "clients": clients,
        "passed": all(
            item["passed"] and item["connections_closed"] for item in clients
        ),
        "requests": 20 * (5 + len(APPLICATION_PATHS)),
    }
    atomic_json(
        Path(os.environ["TGEN_RESULTS_DIR"]) / "multiclient-evidence.json", receipt
    )
    return int(not receipt["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
