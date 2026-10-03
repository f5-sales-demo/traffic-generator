"""Native scanner phases require their own started IDs and completed status."""

COMPLETED_STATUS = 100


def verify_scanner_phases(contract: dict, events: list[dict]) -> dict:
    """Reject missing phases, unrelated IDs and incomplete scans."""
    checks = []
    for path in contract["paths"]:
        starts = [
            event
            for event in events
            if event.get("phase") == contract["phase"]
            and event.get("path") == path
            and event.get("started") is True
        ]
        passed = bool(starts) and all(
            any(
                end.get("phase") == contract["phase"]
                and end.get("scan_id") == start.get("scan_id")
                and end.get("completed") is True
                and end.get("status") == COMPLETED_STATUS
                for end in events
            )
            for start in starts
        )
        checks.append({"path": path, "passed": passed})
    return {
        "passed": bool(checks) and all(check["passed"] for check in checks),
        "checks": checks,
    }
