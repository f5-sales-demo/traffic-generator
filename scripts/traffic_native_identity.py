"""Application-specific native response identity; no inferred exploit or mitigation success."""

import json
import re

HTTP_SUCCESS = 200
HTTP_NOT_FOUND = 404
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


def native_identity(  # noqa: PLR0911  # pylint: disable=too-many-return-statements
    path: str, method: str, status: int | None, content_type: str, body: str
) -> bool:
    """Reject a wrong-content success and classify expected native protocol rejections."""
    if status is None:
        return False
    media = content_type.partition(";")[0]
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
            return False
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
    if (
        path.startswith("/vampi/")
        and status >= HTTP_ERROR_START
        and media == "text/html"
    ):
        return "404 Not Found" in body or "405 Method Not Allowed" in body
    if path.startswith("/vampi/"):
        return document is not None and (
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
            or missing_order_identity(path, method, status, media, body)
            or (
                path == "/crapi/community/api/v2/coupon/validate-coupon"
                and method == "POST"
                and status == NATIVE_MISSING_ORDER_STATUS
                and media == "application/json"
                and document == {}
            )
        )
    if path.startswith("/dvwa/"):
        return dvwa_identity(path, method, status, media, body)
    if path.startswith("/dvga/"):
        return (
            isinstance(document, (dict, list))
            and (isinstance(document, list) or bool(set(document) & {"data", "errors"}))
        ) or (media == "text/html" and ("GraphQL" in body or "Paste" in body))
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
