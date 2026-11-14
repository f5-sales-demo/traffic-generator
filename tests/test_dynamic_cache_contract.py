"""Dynamic application query responses must preserve values and declared cache mode."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_cache import validate_dynamic_response


def test_dynamic_query_cannot_pass_wrong_content_or_cross_contamination():
    assert validate_dynamic_response(
        "/httpbin/get",
        "application/json",
        b'{"headers":{},"args":{"user":"alpha"}}',
        "NONE",
        {"user": "alpha"},
    )
    assert not validate_dynamic_response(
        "/httpbin/get",
        "application/json",
        b'{"headers":{},"args":{"user":"bravo"}}',
        "NONE",
        {"user": "alpha"},
    )
    assert not validate_dynamic_response(
        "/httpbin/get", "text/html", b"Origin Server", "NONE", {}
    )
    assert not validate_dynamic_response(
        "/httpbin/get", "application/json", b'{"headers":{},"args":{}}', "HIT", {}
    )
