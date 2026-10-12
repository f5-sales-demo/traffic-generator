"""Read native response cookies from separate HTTP header fields."""

from http.cookies import SimpleCookie


def native_session_cookie(fields: list[str]) -> str | None:
    """Keep one exact numeric cookie and reject duplicate or malformed values."""
    values = []
    for field in fields:
        cookies = SimpleCookie()
        cookies.load(field)
        if "dvwaSession" in cookies:
            values.append(cookies["dvwaSession"].value)
    return values[0] if len(values) == 1 and values[0].isdigit() else None
