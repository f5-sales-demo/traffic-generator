"""Native scanner phases require their own started IDs and completed status."""

COMPLETED_STATUS = 100


def valid_messages(event: dict, minimum: int) -> bool:
    """Only distinct native scanner history IDs establish emitted attack messages."""
    if not minimum:
        return True
    messages = event.get("message_ids")
    return (
        isinstance(messages, list)
        and len(messages) >= minimum
        and all(isinstance(item, str) and item.isdigit() for item in messages)
        and len(set(messages)) == len(messages)
    )


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
                and valid_messages(end, contract.get("minimum_messages", 0))
                for end in events
            )
            for start in starts
        )
        checks.append({"path": path, "passed": passed})
    return {
        "passed": bool(checks) and all(check["passed"] for check in checks),
        "checks": checks,
    }
