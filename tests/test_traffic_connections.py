"""Bounded TLS assessments retain protocol, cipher, certificate and vulnerability scope."""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_connections import tls_matrix  # noqa: E402 - scripts under test


def test_tls_equivalents_cover_deprecated_protocols_and_cipher_assessment():
    checks = tls_matrix("ssl-scanning/03-testssl")
    assert any(c["protocol"] == "TLSv1" for c in checks)
    assert any(c.get("cipher") for c in checks)
    assert any(c.get("certificate") for c in checks)
    assert len(checks) <= 80
