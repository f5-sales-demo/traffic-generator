#!/usr/bin/env python3
"""Paced equivalents for TLS, port, and slow-header scenarios on authorized hosts."""

import contextlib
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any

from traffic_common import Pacer

HTTPS_PORT = 443


def main() -> int:
    """Run the named connection behavior within independent recorded limits."""
    identifier, host = sys.argv[1:3]
    if host != os.environ.get("TGEN_AUTHORIZED_HOST"):
        msg = "connection target is not authorized"
        raise ValueError(msg)
    rate = min(20, int(os.environ["TGEN_CONNECTION_RATE"]))
    pacer = Pacer(rate)
    results = []
    slow = "slowloris" in identifier
    connections = []
    try:
        if slow:
            count = min(20, int(os.environ["TGEN_SLOW_CONNECTIONS"]))
            for _ in range(count):
                pacer.acquire()
                connection = ssl.create_default_context().wrap_socket(
                    socket.create_connection((host, 443), timeout=5),
                    server_hostname=host,
                )
                connection.sendall(
                    ("GET / HTTP/1.1\r\nHost: " + host + "\r\n").encode()
                )
                connections.append(connection)
                results.append(
                    {"port": 443, "connected": True, "tls": connection.version()}
                )
            for _ in range(3):
                time.sleep(5)
                for connection in connections:
                    with contextlib.suppress(OSError):
                        connection.sendall(b"X-Synthetic-Slow: bounded\r\n")
        else:
            ports = [80, 443] if "ssl-scanning" not in identifier else [443]
            for port in ports:
                for version in (
                    [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]
                    if port == HTTPS_PORT
                    else [None]
                ):
                    pacer.acquire()
                    result: dict[str, Any] = {"port": port, "attempted": time.time()}
                    try:
                        with socket.create_connection(
                            (host, port), timeout=5
                        ) as tcp_probe:
                            if version:
                                context = ssl.create_default_context()
                                context.minimum_version = context.maximum_version = (
                                    version
                                )
                                with context.wrap_socket(
                                    tcp_probe, server_hostname=host
                                ) as secured:
                                    result.update(
                                        connected=True,
                                        tls=secured.version(),
                                        cipher=(secured.cipher() or ("unknown",))[0],
                                    )
                            else:
                                result["connected"] = True
                    except OSError:
                        result["connected"] = False
                    results.append(result)
    finally:
        for connection in connections:
            connection.close()
    receipt = {
        "scenario": identifier,
        "execution": "bounded connection equivalent",
        "scope": "authorized application ports 80 and 443",
        "attempts": len(results),
        "attempt_limit_per_second": rate,
        "maximum_slow_connections": len(connections),
        "results": results,
    }
    path = Path(os.environ["TGEN_RESULTS_DIR"]) / "connections.json"
    path.write_text(json.dumps(receipt) + "\n")
    path.chmod(0o600)
    print(json.dumps(receipt))
    return 0 if any(r.get("connected") for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
