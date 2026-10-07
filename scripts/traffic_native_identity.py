"""Application-specific native response identity; no inferred exploit or mitigation success."""

import json

HTTP_ERROR_START = 400


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
                        }
                    )
                )
            )
        ) or (media == "text/html" and ("crAPI" in body or "MailHog" in body))
    if path.startswith("/dvwa/"):
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
