"""Concrete connection behavior cannot pass from an arbitrary attempt count."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_connections import tls_matrix  # noqa: E402
from traffic_dispatch import declared_socket_cleanup, verify_connection_probe  # noqa: E402


def test_tls_probe_requires_all_offerings_and_certificate():
    identifier = "ssl-scanning/01-sslscan"
    results = [dict(check, connected=True) for check in tls_matrix(identifier)]
    results[2]["certificate_validated"] = True
    receipt = {"scenario": identifier, "results": results, "attempts": len(results),
               "attempt_limit_per_second": 20, "connections_closed": True}
    assert verify_connection_probe(identifier, receipt)["passed"]
    results.pop()
    receipt["attempts"] = len(results)
    assert not verify_connection_probe(identifier, receipt)["passed"]


def test_slow_probe_requires_partial_headers_duration_and_cleanup():
    identifier = "traffic-generation/02-slowloris"
    receipt = {"scenario": identifier, "results": [{"connected": True}], "attempts": 1,
               "attempt_limit_per_second": 20, "connections_closed": True,
               "maximum_slow_connections": 1, "slow_header_writes": 3, "elapsed_seconds": 15}
    assert verify_connection_probe(identifier, receipt)["passed"]
    receipt["slow_header_writes"] = 0
    assert not verify_connection_probe(identifier, receipt)["passed"]


def test_only_declared_long_poll_cleanup_is_expected():
    path = "/juice-shop/socket.io/?transport=polling&sid=synthetic"
    metadata = {"id": "csd-violations/login-credential-skimmer"}
    marker = {"phase": "closing-browser"}
    assert declared_socket_cleanup(path, metadata, marker)
    assert not declared_socket_cleanup(path, metadata, {})
    assert not declared_socket_cleanup("/juice-shop/assets/logo.png", metadata, marker)
    assert not declared_socket_cleanup(path, {"id": "dvga-exploits/query"}, marker)
    assert not declared_socket_cleanup("/juice-shop/socket.io/?transport=polling", metadata, marker)
