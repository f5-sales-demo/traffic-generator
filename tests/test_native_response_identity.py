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


def test_declared_health_identity_requires_exact_inventory_and_route():
    body = json.dumps(
        {
            "status": "healthy",
            "component": "origin-server",
            "applications": [
                "juice-shop",
                "dvwa",
                "vampi",
                "httpbin",
                "whoami",
                "csd-demo",
                "dvga",
                "restaurant",
                "crapi",
            ],
        }
    )
    assert native_identity("/health", "GET", 200, "application/json", body)
    assert not native_identity("/health", "POST", 200, "application/json", body)
    assert not native_identity(
        "/health", "GET", 200, "application/json", '{"status":"healthy"}'
    )


def test_httpbin_headers_identity_is_endpoint_scoped():
    body = '{"headers":{"Host":"demo.example.test","User-Agent":"synthetic"}}'
    assert native_identity("/httpbin/headers", "GET", 200, "application/json", body)
    assert not native_identity("/httpbin/get", "GET", 200, "application/json", body)
    assert not native_identity(
        "/httpbin/headers", "POST", 200, "application/json", body
    )
    assert not native_identity(
        "/httpbin/headers", "GET", 200, "application/json", '{"headers":{}}'
    )


def test_csd_checkout_identity_requires_declared_page_markers():
    body = '<title>ShopDemo - Checkout</title><div id="attackPanel"></div><form id="checkoutForm"></form>'
    assert native_identity("/csd-demo/", "GET", 200, "text/html", body)
    assert not native_identity(
        "/csd-demo/", "GET", 200, "text/html", "<title>ShopDemo - Checkout</title>"
    )
    assert not native_identity("/csd-demo/other", "GET", 200, "text/html", body)


def test_native_captcha_error_requires_exact_route_method_status_and_body():
    body = "Wrong answer to CAPTCHA. Please try again."
    assert native_identity("/juice-shop/api/Feedbacks/", "POST", 401, "text/html", body)
    assert not native_identity(
        "/juice-shop/api/Feedbacks/", "GET", 401, "text/html", body
    )
    assert not native_identity(
        "/juice-shop/rest/user/login", "POST", 401, "text/html", body
    )
    assert not native_identity(
        "/juice-shop/api/Feedbacks/", "POST", 401, "text/html", body + "unexpected"
    )


def test_origin_landing_and_csd_health_require_declared_content():
    landing = '<title>Origin Server</title><a href="/health">Health Check</a><a href="/juice-shop/"></a><a href="/crapi/"></a>'
    assert native_identity("/", "GET", 200, "text/html", landing)
    assert not native_identity("/", "GET", 200, "text/html", "Origin Server")
    health = json.dumps(
        {
            "status": "healthy",
            "component": "csd-demo",
            "attacks": [
                "skimmer",
                "formjacker",
                "keylogger",
                "cryptominer",
                "dom-hijack",
            ],
        }
    )
    assert native_identity("/csd-demo/health", "GET", 200, "application/json", health)
    assert not native_identity(
        "/csd-demo/health", "GET", 200, "application/json", '{"status":"healthy"}'
    )


def test_csd_exfil_and_native_markdown_require_exact_route_content():
    assert native_identity(
        "/csd-demo/exfil", "POST", 200, "application/json", '{"status":"received"}'
    )
    assert not native_identity(
        "/csd-demo/exfil", "GET", 200, "application/json", '{"status":"received"}'
    )
    assert native_identity("/csd-demo/exfil/log", "GET", 200, "application/json", "[]")
    assert not native_identity(
        "/csd-demo/exfil/log", "GET", 200, "application/json", "[{}]"
    )
    assert native_identity(
        "/juice-shop/ftp/acquisitions.md",
        "GET",
        200,
        "text/markdown",
        "# Planned Acquisitions\nSynthetic text",
    )
    assert not native_identity(
        "/juice-shop/ftp/acquisitions.md", "GET", 200, "text/markdown", "Generic text"
    )


def test_native_dvwa_directory_denial_is_exact_and_route_scoped():
    body = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
    assert native_identity("/dvwa/vulnerabilities/", "GET", 403, "text/html", body)
    padding = "<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n"
    assert native_identity(
        "/dvwa/vulnerabilities/", "GET", 403, "text/html", body + padding * 6
    )
    assert not native_identity(
        "/dvwa/vulnerabilities/", "GET", 403, "text/html", body + padding * 5
    )
    assert not native_identity(
        "/dvwa/vulnerabilities/", "GET", 403, "text/html", body + padding * 7
    )
    assert not native_identity(
        "/dvwa/vulnerabilities/sqli/", "GET", 403, "text/html", body
    )
    assert not native_identity("/dvwa/vulnerabilities/", "POST", 403, "text/html", body)
    assert not native_identity(
        "/dvwa/vulnerabilities/", "GET", 403, "text/html", "Request Rejected"
    )


def test_native_coupon_requires_exact_route_code_and_amount():
    body = '{"coupon_code":"TRAC075","amount":75,"CreatedAt":"synthetic"}'
    assert native_identity(
        "/crapi/community/api/v2/coupon/validate-coupon",
        "POST",
        200,
        "application/json",
        body,
    )
    assert not native_identity(
        "/crapi/identity/api/auth/login", "POST", 200, "application/json", body
    )
    assert not native_identity(
        "/crapi/community/api/v2/coupon/validate-coupon",
        "POST",
        200,
        "application/json",
        '{"coupon_code":"TRAC075"}',
    )


def test_native_coupon_observed_decimal_string_is_route_scoped():
    path = "/crapi/community/api/v2/coupon/validate-coupon"
    assert native_identity(
        path,
        "POST",
        200,
        "application/json",
        '{"coupon_code":"TRAC075","amount":"75","CreatedAt":"synthetic"}',
    )
    for amount in ["", "unknown", "NaN", "Infinity", True, None]:
        body = json.dumps({"coupon_code": "TRAC075", "amount": amount})
        assert not native_identity(path, "POST", 200, "application/json", body)
    assert not native_identity(
        "/crapi/unknown",
        "POST",
        200,
        "application/json",
        '{"coupon_code":"TRAC075","amount":"75"}',
    )
