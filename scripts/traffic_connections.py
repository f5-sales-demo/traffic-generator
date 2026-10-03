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


def tls_matrix(identifier: str) -> list[dict]:
    """Assess accepted/deprecated protocols, cipher families and the verified certificate."""
    checks: list[dict[str, Any]] = [
        {"protocol": name} for name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3")
    ]
    checks[2]["certificate"] = True
    if "ssl-scanning" in identifier:
        checks.extend(
            {"protocol": "TLSv1_2", "cipher": cipher}
            for cipher in (
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                "AES128-SHA",
                "AES256-SHA",
                "AES128-GCM-SHA256",
                "AES256-GCM-SHA384",
            )
        )
    return checks


def tls_probe(host: str, check: dict) -> dict:
    """Make one bounded handshake; distinguish a rejected offering from unreachable TLS."""
    result = dict(check, port=443, attempted=time.time())
    context = ssl.create_default_context()
    version = getattr(ssl.TLSVersion, check["protocol"])
    context.minimum_version = context.maximum_version = version
    context.set_alpn_protocols(["h2", "http/1.1"])
    if check.get("cipher"):
        context.set_ciphers(check["cipher"] + ":@SECLEVEL=0")
    elif check["protocol"] in ("TLSv1", "TLSv1_1"):
        context.set_ciphers("ALL:@SECLEVEL=0")
    try:
        with (
            socket.create_connection((host, 443), timeout=5) as connection,
            context.wrap_socket(connection, server_hostname=host) as secured,
        ):
            result.update(
                connected=True,
                tls=secured.version(),
                cipher=(secured.cipher() or ("unknown",))[0],
                compression=secured.compression(),
                alpn=secured.selected_alpn_protocol(),
            )
            if check.get("certificate"):
                certificate = secured.getpeercert() or {}
                result["certificate_validated"] = True
                result["certificate_expires"] = certificate.get("notAfter")
    except ssl.SSLError as error:
        result.update(connected=False, rejection=type(error).__name__)
    except OSError as error:
        result.update(connected=False, transport_failure=type(error).__name__)
    return result


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
    slow_header_writes = 0
    started = time.monotonic()
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
                        slow_header_writes += 1
        else:
            if "ssl-scanning" not in identifier:
                pacer.acquire()
                try:
                    with socket.create_connection((host, 80), timeout=5):
                        results.append({"port": 80, "connected": True})
                except OSError:
                    results.append(
                        {"port": 80, "connected": False, "transport_failure": True}
                    )
            for check in tls_matrix(identifier):
                pacer.acquire()
                results.append(tls_probe(host, check))
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
        "elapsed_seconds": time.monotonic() - started,
        "slow_header_writes": slow_header_writes,
        "connections_closed": all(
            connection.fileno() == -1 for connection in connections
        ),
    }
    path = Path(os.environ["TGEN_RESULTS_DIR"]) / "connections.json"
    path.write_text(json.dumps(receipt) + "\n")
    path.chmod(0o600)
    print(json.dumps(receipt))
    return (
        0
        if any(r.get("connected") for r in results)
        and not any(r.get("transport_failure") for r in results)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
