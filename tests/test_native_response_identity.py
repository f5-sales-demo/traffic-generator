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


def test_declared_native_error_shapes_are_content_verified():
    assert native_identity(
        "/vampi/missing", "GET", 404, "text/html", "<h1>404 Not Found</h1>"
    )
    assert not native_identity(
        "/vampi/missing", "GET", 404, "text/html", "generic landing"
    )
    assert native_identity(
        "/crapi/identity/api/v2/admin/users/debug",
        "GET",
        401,
        "application/json",
        '{"error":"Unauthorized","path":"/api/v2/admin/users/debug"}',
    )
    assert not native_identity(
        "/crapi/identity/api/v2/admin/users/debug",
        "GET",
        401,
        "application/json",
        '{"unrelated":true}',
    )


def test_order_missing_object_error_is_exact_and_endpoint_scoped():
    body = "<title>Server Error (500)</title><h1>Server Error (500)</h1>"
    assert native_identity(
        "/crapi/workshop/api/shop/orders/20", "GET", 500, "text/html", body
    )
    assert not native_identity(
        "/crapi/workshop/api/shop/orders/20", "GET", 500, "text/html", "generic error"
    )
    assert not native_identity(
        "/crapi/identity/api/auth/login", "POST", 500, "text/html", body
    )
    assert native_identity(
        "/crapi/workshop/api/shop/orders/1",
        "GET",
        200,
        "application/json",
        '{"order":{"id":1}}',
    )


def test_native_validation_media_and_empty_coupon_error_are_route_scoped():
    assert native_identity(
        "/crapi/identity/api/auth/login",
        "POST",
        415,
        "application/problem+json",
        '{"title":"Unsupported Media Type","status":415}',
    )
    assert native_identity(
        "/crapi/community/api/v2/coupon/validate-coupon",
        "POST",
        500,
        "application/json",
        "{}",
    )
    assert not native_identity(
        "/crapi/identity/api/auth/login", "POST", 500, "application/json", "{}"
    )
    assert not native_identity(
        "/crapi/community/api/v2/coupon/validate-coupon",
        "POST",
        200,
        "application/json",
        "{}",
    )
