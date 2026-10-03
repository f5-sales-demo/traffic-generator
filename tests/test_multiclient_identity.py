"""Client isolation is verified from returned synthetic identity markers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_multiclient import identity_matches


def test_another_clients_cookie_or_forwarded_identity_fails():
    headers = {
        "True-Client-Ip": "192.0.2.17",
        "Fastly-Client-Ip": "192.0.2.17",
        "Cookie": "tgen_client=client-17",
    }
    assert identity_matches(headers, "192.0.2.17", "client-17")
    assert not identity_matches(headers, "192.0.2.18", "client-17")
    assert not identity_matches(headers, "192.0.2.17", "client-18")
