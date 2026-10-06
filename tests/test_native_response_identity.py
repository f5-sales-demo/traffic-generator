"""Native protocol identity rejects wrong-content 200s and preserves failure boundaries."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_native_identity import native_identity


def test_native_identity_rejects_generic_landing_on_api_route():
    assert not native_identity(
        "/vampi/users/v1", "GET", 200, "text/html", "Origin Server"
    )
    assert native_identity(
        "/vampi/users/v1", "GET", 200, "application/json", '{"users":["synthetic"]}'
    )
    assert not native_identity(
        "/crapi/identity/api/auth/login", "POST", 200, "application/json", "{}"
    )
    assert not native_identity(
        "/vampi/", "GET", None, "application/json", '{"message":"VAmPI"}'
    )


def test_httpbin_requires_an_actual_echo_or_native_rejection():
    assert native_identity(
        "/httpbin/get",
        "GET",
        200,
        "application/json",
        '{"url":"http://example.test/httpbin/get","headers":{}}',
    )
    assert not native_identity(
        "/httpbin/get", "GET", 200, "application/json", '{"unrelated":true}'
    )
    assert not native_identity(
        "/dvwa/vulnerabilities/sqli/",
        "GET",
        200,
        "text/html",
        '<a href="login.php">DVWA</a>',
    )


def test_denial_status_does_not_establish_native_application_identity():
    assert not native_identity(
        "/vampi/users/v1", "GET", 403, "text/html", "Request blocked"
    )
    assert not native_identity(
        "/crapi/identity/api/auth/login", "POST", 429, "text/plain", "Too many requests"
    )
