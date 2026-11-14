#!/usr/bin/env python3
"""Native bounded socket probes for declared TLS and slow-header behaviors."""

import os
import socket
import ssl
import sys
import time
from typing import Any

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
    _identifier, host = sys.argv[1:3]
    if host != os.environ.get("TGEN_AUTHORIZED_HOST"):
        msg = "connection target is not authorized"
        raise ValueError(msg)
    message = (
        "generic socket substitution retired; invoke the declared native tool adapter"
    )
    raise ValueError(message)


if __name__ == "__main__":
    raise SystemExit(main())
