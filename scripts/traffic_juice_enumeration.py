"""Exact protocol identity for pinned native Juice Shop enumeration endpoints."""

import hashlib
import json
import re

HTTP_SUCCESS = 200
HTTP_UNAUTHORIZED = 401


def juice_generated_identity(
    path: str, method: str, status: int, media: str, body: str
) -> bool | None:
    """Validate native generated continue codes and B2B order response fields."""
    if path == "/juice-shop/b2b/v2/orders" and status == HTTP_UNAUTHORIZED:
        return (
            method == "POST"
            and media == "text/html"
            and all(
                term in body
                for term in (
                    "<title>UnauthorizedError: No Authorization header was found</title>",
                    "<h1>OWASP Juice Shop (Express ^4.22.1)</h1>",
                    "<h2><em>401</em> UnauthorizedError: No Authorization header was found</h2>",
                )
            )
        )
    if path in {"/juice-shop/rest/continue-code", "/juice-shop/b2b/v2/orders"}:
        try:
            document = json.loads(body)
        except ValueError:
            return False
        if (
            status != HTTP_SUCCESS
            or media != "application/json"
            or not isinstance(document, dict)
        ):
            return False
        if path == "/juice-shop/rest/continue-code":
            return method == "GET" and (
                document == {}
                or (
                    set(document) == {"continueCode"}
                    and isinstance(document["continueCode"], str)
                    and re.fullmatch(r"[A-Za-z0-9]{60,}", document["continueCode"])
                    is not None
                )
            )
        return (
            method == "POST"
            and {"orderNo", "paymentDue"}
            <= set(document)
            <= {"cid", "orderNo", "paymentDue"}
            and isinstance(document["orderNo"], str)
            and re.fullmatch(r"[a-f0-9]{32}", document["orderNo"]) is not None
            and isinstance(document["paymentDue"], str)
            and re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
                document["paymentDue"],
            )
            is not None
        )
    return None


def juice_enumeration_identity(
    path: str, method: str, status: int, media: str, body: str
) -> bool | None:
    """Bind native enumeration support endpoints to exact protocol responses."""
    if path == "/juice-shop/rest/saveLoginIp" and status == HTTP_UNAUTHORIZED:
        return method == "GET" and media == "text/plain" and body == "Unauthorized"
    if path == "/juice-shop/rest/repeat-notification" and status == HTTP_SUCCESS:
        return method == "GET" and media == "text/plain" and body == "OK"
    if path == "/juice-shop/rest/country-mapping" and status == HTTP_SUCCESS:
        return (
            method == "GET"
            and media == "application/json"
            and hashlib.sha256(body.encode()).hexdigest()
            == "488f0bbcc11b14d6c2dd10e0ccd3ac5b7b68d8368623b75aef25e6767c50b6ea"
        )
    return None
