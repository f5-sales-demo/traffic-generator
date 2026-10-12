"""Application-specific native response identity; no inferred exploit or mitigation success."""

import json
import re

HTTP_SUCCESS = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_TOO_LARGE = 413
HTTP_ERROR_START = 400
NATIVE_MISSING_ORDER_STATUS = 500


def missing_order_identity(
    path: str, method: str, status: int | None, media: str, body: str
) -> bool:
    """Recognize only the observed native missing-order response on its exact route."""
    return (
        re.fullmatch(r"/crapi/workshop/api/shop/orders/[0-9]+", path) is not None
        and method == "GET"
        and status == NATIVE_MISSING_ORDER_STATUS
        and media == "text/html"
        and all(
            text in body
            for text in (
                "<title>Server Error (500)</title>",
                "<h1>Server Error (500)</h1>",
            )
        )
    )


def dvwa_identity(path: str, method: str, status: int, media: str, body: str) -> bool:
    """Recognize owned upload execution or authenticated DVWA pages."""
    if path == "/dvwa/vulnerabilities/" and status == HTTP_FORBIDDEN:
        return (
            method == "GET"
            and media == "text/html"
            and body
            in {
                "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n"
                "<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n"
                "</body>\r\n</html>\r\n",
                "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n"
                "<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n"
                "</body>\r\n</html>\r\n"
                + "<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n"
                * 6,
            }
        )
    if re.fullmatch(r"/dvwa/hackable/uploads/tgen-[a-f0-9]{32}-shell\.php", path):
        return (
            method == "GET"
            and media == "text/html"
            and (
                (status == HTTP_SUCCESS and "UPLOAD_SUCCESS" in body and "uid=" in body)
                or (
                    status == HTTP_NOT_FOUND
                    and "Not Found" in body
                    and "The requested URL was not found" in body
                )
            )
        )
    return (
        media == "text/html"
        and "DVWA" in body
        and (
            "login.php" not in body
            or "Logout" in body
            or path.endswith("login.php")
            or status >= HTTP_ERROR_START
        )
    )


def vampi_problem_identity(status: int, body: str) -> bool:
    """Recognize only the exact observed prefix-adapter problem errors."""
    try:
        problem = json.loads(body)
    except ValueError:
        return False
    expected = {
        401: ("Unauthorized", "No authorization token provided"),
        404: (
            "Not Found",
            "The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.",
        ),
        405: ("Method Not Allowed", "The method is not allowed for the requested URL."),
    }.get(status)
    return expected is not None and problem == {
        "type": "about:blank",
        "status": status,
        "title": expected[0],
        "detail": expected[1],
    }


def vampi_identity(status: int, media: str, body: str, document: object) -> bool:
    """Recognize the native application and its exact prefix-adapter errors."""
    if media == "application/problem+json":
        return vampi_problem_identity(status, body)
    if status >= HTTP_ERROR_START and media == "text/html":
        return "404 Not Found" in body or "405 Method Not Allowed" in body
    return (
        document is not None
        and not (isinstance(document, dict) and document.get("type") == "about:blank")
        and (
            isinstance(document, list)
            or (
                isinstance(document, dict)
                and bool(
                    set(document)
                    & {
                        "message",
                        "auth_token",
                        "users",
                        "Books",
                        "book_title",
                        "error",
                        "status",
                        "openapi",
                        "User",
                        "username",
                    }
                )
            )
        )
    )


def crapi_known_error(
    path: str, method: str, status: int, media: str, body: str
) -> bool:
    """Accept exact observed protocol errors on the two declared discovery routes."""
    if path == "/crapi/identity/api/v2/admin/users/debug":
        return (
            method == "GET"
            and status == HTTP_UNAUTHORIZED
            and media == "application/json"
            and body.strip() == "CRAPIResponse(message=Invalid Token, status=401)"
        )
    return (
        path == "/crapi/workshop/api/internal/metrics"
        and method == "GET"
        and status == HTTP_NOT_FOUND
        and media == "text/html"
        and all(
            value in body
            for value in (
                "<title>Not Found</title>",
                "<h1>Not Found</h1>",
                "The requested resource was not found on this server.",
            )
        )
    )


def auxiliary_identity(
    path: str, method: str, status: int, media: str, body: str, document: object
) -> bool:
    """Recognize exact health, header echo, checkout and CAPTCHA responses."""
    if path == "/health":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and media == "application/json"
            and document
            == {
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
    if path == "/httpbin/headers" and status == HTTP_SUCCESS:
        return (
            method == "GET"
            and media == "application/json"
            and isinstance(document, dict)
            and set(document) == {"headers"}
            and isinstance(document["headers"], dict)
            and bool(document["headers"].get("Host"))
        )
    if path == "/csd-demo/":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and media == "text/html"
            and all(
                value in body
                for value in (
                    "<title>ShopDemo - Checkout</title>",
                    'id="attackPanel"',
                    'id="checkoutForm"',
                )
            )
        )
    if path == "/juice-shop/api/Feedbacks/" and status == HTTP_UNAUTHORIZED:
        return (
            method == "POST"
            and media == "text/html"
            and body == "Wrong answer to CAPTCHA. Please try again."
        )
    return False


def review_update_identity(document: object) -> bool:
    """Require native MarsDB update count and unchanged review identities."""
    if not isinstance(document, dict) or set(document) != {
        "modified",
        "original",
        "updated",
    }:
        return False
    count = document["modified"]
    before, after = document["original"], document["updated"]
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        or not isinstance(before, list)
        or not isinstance(after, list)
    ):
        return False
    if len(before) != count or len(after) != count:
        return False
    return all(
        isinstance(old, dict)
        and isinstance(new, dict)
        and {"_id", "product", "message", "author"} <= set(old)
        and {"_id", "product", "message", "author"} <= set(new)
        and all(old[key] == new[key] for key in ("_id", "product", "author"))
        and isinstance(new["message"], str)
        for old, new in zip(before, after, strict=True)
    )


def declared_support_identity(
    path: str, method: str, status: int, media: str, body: str, document: object
) -> bool | None:
    """Recognize exact declared support pages; None delegates to app classifiers."""
    if path == "/" and method == "GET" and status == HTTP_SUCCESS:
        return media == "text/html" and all(
            value in body
            for value in (
                "<title>Origin Server</title>",
                '<a href="/health">Health Check</a>',
                '<a href="/juice-shop/">',
                '<a href="/crapi/">',
            )
        )
    if path == "/csd-demo/health":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and media == "application/json"
            and document
            == {
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
    if path == "/csd-demo/exfil":
        return (
            method == "POST"
            and status == HTTP_SUCCESS
            and document == {"status": "received"}
        )
    if path == "/csd-demo/exfil/log":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and isinstance(document, list)
            and all(
                isinstance(row, dict)
                and {"fixture_id", "timestamp", "attack_type", "payload"} <= set(row)
                for row in document
            )
        )
    if path == "/juice-shop/ftp/acquisitions.md":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and media == "text/markdown"
            and body.startswith("# Planned Acquisitions\n")
        )
    return None


def native_identity(  # noqa: PLR0911  # pylint: disable=too-many-return-statements,too-many-branches
    path: str, method: str, status: int | None, content_type: str, body: str
) -> bool:
    """Reject a wrong-content success and classify expected native protocol rejections."""
    if status is None:
        return False
    media = content_type.partition(";")[0]
    if method == "CONNECT":
        return (
            status == HTTP_BAD_REQUEST
            and path
            in {"/vampi/users/v1", "/juice-shop/rest/products/search", "/dvwa/"}
            and media == "text/plain"
            and body == "Bad Request"
        )

    if method == "HEAD" or status in (204, 304):
        return body == ""
    if status in (301, 302, 307, 308):
        return media == "text/html" and ("Redirect" in body or "redirect" in body)
    document = None
    media = (
        "application/json"
        if path.startswith("/crapi/") and media == "application/problem+json"
        else media
    )
    if media in ("application/json", "text/json"):
        try:
            document = json.loads(body)
        except ValueError:
            return crapi_known_error(path, method, status, media, body)
    support = declared_support_identity(path, method, status, media, body, document)
    if support is not None:
        return support
    if path in {"/health", "/httpbin/headers", "/csd-demo/"} or (
        path == "/juice-shop/api/Feedbacks/" and status == HTTP_UNAUTHORIZED
    ):
        return auxiliary_identity(path, method, status, media, body, document)
    if path.startswith("/httpbin/"):
        return (
            isinstance(document, dict)
            and (
                ("url" in document and ("headers" in document or "origin" in document))
                or (status >= HTTP_ERROR_START and bool(document))
            )
        ) or (
            media == "text/html"
            and (
                "httpbin" in body.casefold()
                or (
                    status >= HTTP_ERROR_START
                    and ("Bad Request" in body or "Not Found" in body)
                )
            )
        )
    if path.startswith("/vampi/"):
        return vampi_identity(status, media, body, document)
    if (
        path == "/crapi/community/api/v2/coupon/validate-coupon"
        and method == "POST"
        and status == HTTP_SUCCESS
    ):
        return (
            media == "application/json"
            and isinstance(document, dict)
            and isinstance(document.get("coupon_code"), str)
            and (
                isinstance(document.get("amount"), (int, float))
                or (
                    isinstance(document.get("amount"), str)
                    and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", document["amount"])
                    is not None
                )
            )
            and not isinstance(document.get("amount"), bool)
        )
    if path.startswith("/crapi/"):
        return (
            (
                document is not None
                and (
                    isinstance(document, list)
                    or (
                        isinstance(document, dict)
                        and bool(
                            set(document)
                            & {
                                "message",
                                "status",
                                "error",
                                "path",
                                "timestamp",
                                "token",
                                "items",
                                "id",
                                "profileVideo",
                                "vehicles",
                                "data",
                                "mechanics",
                                "posts",
                                "video_name",
                                "vehicle",
                                "name",
                                "email",
                                "content",
                                "count",
                                "title",
                                "order",
                                "payment",
                            }
                        )
                    )
                )
            )
            or (media == "text/html" and ("crAPI" in body or "MailHog" in body))
            or crapi_known_error(path, method, status, media, body)
            or missing_order_identity(path, method, status, media, body)
            or (
                path == "/crapi/community/api/v2/coupon/validate-coupon"
                and method == "POST"
                and status == NATIVE_MISSING_ORDER_STATUS
                and media == "application/json"
                and document == {}
            )
        )
    if (
        path == "/dvwa/vulnerabilities/upload/"
        and method == "POST"
        and status == HTTP_TOO_LARGE
    ):
        return media == "text/html" and all(
            value in body
            for value in (
                "<title>413 Request Entity Too Large</title>",
                "<h1>413 Request Entity Too Large</h1>",
                "nginx",
            )
        )
    if path.startswith("/dvwa/"):
        return dvwa_identity(path, method, status, media, body)
    if path.startswith("/dvga/"):
        return (
            isinstance(document, (dict, list))
            and (isinstance(document, list) or bool(set(document) & {"data", "errors"}))
        ) or (media == "text/html" and ("GraphQL" in body or "Paste" in body))
    if (
        path == "/juice-shop/rest/user/whoami"
        and method == "GET"
        and status == HTTP_SUCCESS
    ):
        return media == "application/json" and document == {"user": {}}
    if path == "/juice-shop/rest/products/reviews" and status == HTTP_SUCCESS:
        return (
            method == "PATCH"
            and media == "application/json"
            and review_update_identity(document)
        )
    if path == "/juice-shop/rest/admin/application-configuration":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and media == "application/json"
            and isinstance(document, dict)
            and set(document) == {"config"}
            and isinstance(document["config"], dict)
            and {
                "application",
                "challenges",
                "ctf",
                "hackingInstructor",
                "memories",
                "products",
                "server",
            }
            <= set(document["config"])
        )
    if path == "/juice-shop/rest/admin/application-version":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and media == "application/json"
            and isinstance(document, dict)
            and set(document) == {"version"}
            and isinstance(document["version"], str)
        )
    if path == "/juice-shop/main.js":
        return (
            method == "GET"
            and status == HTTP_SUCCESS
            and media == "application/javascript"
            and all(
                term in body
                for term in (
                    "application-configuration",
                    "application-version",
                    "juice-shop",
                    "Juice Shop",
                )
            )
        )
    if path == "/juice-shop/api/BasketItems/" and status == HTTP_UNAUTHORIZED:
        return (
            method == "POST"
            and media == "text/html"
            and body == "{'error' : 'Invalid BasketId'}"
        )
    if path.startswith("/juice-shop/"):
        return (
            media == "text/html"
            and (
                "Juice Shop" in body or (status >= HTTP_ERROR_START and "Error" in body)
            )
        ) or (
            document is not None
            and (
                isinstance(document, list)
                or (
                    isinstance(document, dict)
                    and bool(
                        set(document)
                        & {
                            "data",
                            "status",
                            "authentication",
                            "error",
                            "languages",
                            "name",
                            "id",
                            "email",
                            "message",
                        }
                    )
                )
            )
        )
    if (
        path == "/restaurant/admin/stats/disk"
        and method == "GET"
        and status == HTTP_SUCCESS
    ):
        return (
            media == "application/json"
            and isinstance(document, dict)
            and set(document) == {"output"}
            and isinstance(document["output"], str)
            and (
                document["output"].startswith("Filesystem") or document["output"] == ""
            )
        )
    if path == "/restaurant/debug" and method == "GET" and status == HTTP_SUCCESS:
        return (
            media == "application/json"
            and isinstance(document, dict)
            and {"os_info", "env_vars", "local_paths", "disk_usage", "memory_usage"}
            <= set(document)
        )
    if path.startswith("/restaurant/"):
        return (
            document is not None
            and (
                isinstance(document, list)
                or (
                    isinstance(document, dict)
                    and bool(
                        set(document)
                        & {
                            "detail",
                            "access_token",
                            "username",
                            "id",
                            "items",
                            "openapi",
                            "message",
                            "name",
                            "role",
                            "token",
                            "email",
                        }
                    )
                )
            )
        ) or (media == "text/html" and ("Swagger" in body or "ReDoc" in body))
    if path.startswith("/whoami/"):
        return media == "text/plain" and "Hostname:" in body
    if status >= HTTP_ERROR_START:
        return bool(body) and (
            document is not None or media in ("text/html", "text/plain")
        )
    return False
