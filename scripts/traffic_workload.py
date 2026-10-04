"""Deterministic bounded load qualifications sharing the namespace HTTP pacing budget."""

import json
from pathlib import Path


def content_identity(path: str, content_type: str, body: bytes) -> bool:
    """Require declared application content and type rather than an arbitrary 200."""
    root = Path(__file__).resolve().parents[1]
    applications = json.loads((root / "suites/applications.json").read_text())[
        "applications"
    ]
    page = next(
        (
            page
            for app in applications
            for page in app["pages"]
            if app["prefix"] + page["path"] == path
        ),
        None,
    )
    if page is None:
        return False
    return (
        content_type.split(";", 1)[0] == page["content_type"]
        and page["identity"].casefold()
        in body.decode("utf-8", errors="replace").casefold()
    )


def main() -> int:
    """Retired substitute; catalog load execution requires native_load.py."""
    message = "Python workload execution retired; use the declared native tool"
    raise ValueError(message)


if __name__ == "__main__":
    raise SystemExit(main())
