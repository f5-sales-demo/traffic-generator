"""Native protocol identity rejects wrong-content 200s and preserves failure boundaries."""

import json
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


def test_vampi_proxy_problem_response_requires_exact_protocol_shape():
    body = json.dumps(
        {
            "type": "about:blank",
            "title": "Method Not Allowed",
            "status": 405,
            "detail": "The method is not allowed for the requested URL.",
        }
    )
    assert native_identity(
        "/vampi/users/v1/_debug", "POST", 405, "application/problem+json", body
    )
    assert not native_identity(
        "/vampi/users/v1/_debug", "POST", 200, "application/problem+json", body
    )
    assert not native_identity(
        "/vampi/users/v1/_debug", "POST", 404, "application/problem+json", body
    )
    assert not native_identity(
        "/vampi/users/v1/_debug", "POST", 405, "application/json", body
    )
    assert not native_identity(
        "/vampi/users/v1/_debug", "POST", 405, "application/problem+json", "{}"
    )


def test_observed_protocol_errors_are_route_and_content_scoped():
    body = json.dumps(
        {
            "type": "about:blank",
            "status": 401,
            "title": "Unauthorized",
            "detail": "No authorization token provided",
        }
    )
    assert native_identity(
        "/vampi/books/v1/not-an-integer", "GET", 401, "application/problem+json", body
    )
    assert not native_identity(
        "/vampi/books/v1/not-an-integer", "GET", 200, "application/problem+json", body
    )
    body = "CRAPIResponse(message=Invalid Token, status=401)\n"
    assert native_identity(
        "/crapi/identity/api/v2/admin/users/debug",
        "GET",
        401,
        "application/json;charset=ISO-8859-1",
        body,
    )
    assert not native_identity(
        "/crapi/identity/api/auth/login", "POST", 401, "application/json", body
    )
    body = "<title>Not Found</title><h1>Not Found</h1><p>The requested resource was not found on this server.</p>"
    assert native_identity(
        "/crapi/workshop/api/internal/metrics", "GET", 404, "text/html", body
    )
    assert not native_identity(
        "/crapi/workshop/api/internal/metrics", "GET", 200, "text/html", body
    )


def test_connect_rejection_is_exact_route_method_status_and_body():
    assert native_identity(
        "/vampi/users/v1", "CONNECT", 400, "text/plain", "Bad Request"
    )
    assert not native_identity(
        "/vampi/users/v1", "GET", 400, "text/plain", "Bad Request"
    )
    assert not native_identity(
        "/unrelated", "CONNECT", 400, "text/plain", "Bad Request"
    )
    assert not native_identity(
        "/vampi/users/v1", "CONNECT", 500, "text/plain", "Bad Request"
    )
