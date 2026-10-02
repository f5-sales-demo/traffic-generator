#!/usr/bin/env python3
"""Bounded keepalive and multi-client equivalents for standalone hardware benches."""

import http.client
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def main() -> int:
    """Preserve multiple paths and connection behavior without host tuning."""
    scenario, domain = sys.argv[1:3]
    if domain != os.environ["TGEN_AUTHORIZED_HOST"]:
        msg = "unauthorized benchmark target"
        raise ValueError(msg)
    paths = ["/httpbin/get", "/juice-shop/", "/dvwa/", "/vampi/"]

    local = threading.local()
    connections = []
    lock = threading.Lock()

    def request(index: int) -> int:
        """Issue requests using actual persistent connections inside the paced namespace."""
        keepalive = "keepalive" in scenario
        if not hasattr(local, "connection") or not keepalive:
            local.connection = http.client.HTTPSConnection(domain, timeout=10)
            with lock:
                connections.append(local.connection)
        try:
            local.connection.request(
                "GET",
                paths[index % len(paths)],
                headers={"Connection": "keep-alive" if keepalive else "close"},
            )
            response = local.connection.getresponse()
            response.read()
        except (OSError, http.client.HTTPException):
            local.connection.close()
            del local.connection
            return 0
        else:
            return response.status
        finally:
            if not keepalive and hasattr(local, "connection"):
                local.connection.close()

    with ThreadPoolExecutor(
        max_workers=min(20, int(os.environ["TGEN_CONCURRENCY"]))
    ) as pool:
        codes = list(pool.map(request, range(int(os.environ["TGEN_REQUESTS"]))))
    for connection in connections:
        connection.close()
    receipt = {
        "scenario": scenario,
        "execution": "bounded benchmark equivalent",
        "requests": len(codes),
        "outcomes": {str(code): codes.count(code) for code in set(codes)},
        "host_tuning": False,
        "connections_created": len(connections),
        "persistent_connections": "keepalive" in scenario,
    }
    path = Path(os.environ["TGEN_RESULTS_DIR"]) / "benchmark.json"
    path.write_text(json.dumps(receipt))
    path.chmod(0o600)
    print(json.dumps(receipt))
    return int(0 in codes)


if __name__ == "__main__":
    raise SystemExit(main())
