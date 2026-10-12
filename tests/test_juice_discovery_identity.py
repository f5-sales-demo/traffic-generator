"""Native discovery content is route-bound and cannot hide generic failures."""

from traffic_native_identity import native_binary_identity, native_identity


def test_exact_juice_native_plain_protocol_responses():
    for path, method, status, body in (
        ("/juice-shop/rest/user/login", "POST", 401, "Invalid email or password."),
        (
            "/juice-shop/rest/user/change-password",
            "GET",
            401,
            "Password cannot be empty.",
        ),
        (
            "/juice-shop/rest/user/reset-password",
            "POST",
            401,
            "Wrong answer to security question.",
        ),
        (
            "/juice-shop/rest/continue-code/apply/test",
            "PUT",
            404,
            "Invalid continue code.",
        ),
        ("/juice-shop/robots.txt", "GET", 200, "User-agent: *\nDisallow: /ftp"),
    ):
        assert native_identity(
            path, method, status, "text/html" if status >= 400 else "text/plain", body
        )
        assert not native_identity(path, method, status, "text/plain", "unrelated")


def test_exact_directory_and_swagger_pages():
    assert native_identity(
        "/juice-shop/ftp/",
        "GET",
        200,
        "text/html",
        "<title>listing directory /ftp/</title>acquisitions.md",
    )
    assert not native_identity(
        "/juice-shop/ftp/",
        "GET",
        200,
        "text/html",
        "<title>listing directory /other/</title>",
    )
    assert native_identity(
        "/juice-shop/api-docs/",
        "GET",
        200,
        "text/html",
        "<title>Swagger UI</title>swagger-ui-bundle.js swagger-ui-init.js",
    )
    assert not native_identity(
        "/juice-shop/api-docs/", "GET", 200, "text/html", "generic page"
    )


def test_prometheus_metrics_have_native_names_and_samples():
    body = "# HELP juiceshop_requests_total Requests\n# TYPE juiceshop_requests_total counter\njuiceshop_requests_total 3\n"
    assert native_identity("/juice-shop/metrics", "GET", 200, "text/plain", body)
    assert not native_identity(
        "/juice-shop/metrics", "GET", 200, "text/plain", "# HELP other Requests\n"
    )


def test_binary_native_assets_require_exact_route_media_and_bytes():
    assert not native_binary_identity(
        "/juice-shop/video", "GET", 200, "video/mp4", b"generic"
    )
    assert not native_binary_identity(
        "/juice-shop/assets/public/images/padding/1px.png",
        "GET",
        200,
        "image/png",
        b"generic",
    )
    assert not native_binary_identity(
        "/foreign/video", "GET", 200, "video/mp4", b"generic"
    )
