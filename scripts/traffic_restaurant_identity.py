"""Exact native RESTaurant responses retained by every catalog boundary."""

import json

HTTP_FORBIDDEN = 403


def restaurant_registration_rejection(
    path: str, method: str, status: int | None, content_type: str, body: str
) -> bool:
    """Match the pinned native registration conflict without claiming a WAAP block."""
    if (
        path != "/restaurant/register"
        or method != "POST"
        or status != HTTP_FORBIDDEN
        or content_type.partition(";")[0] != "application/json"
    ):
        return False
    try:
        document = json.loads(body)
    except ValueError:
        return False
    return document == {"detail": "Username or phone number already registered."}
