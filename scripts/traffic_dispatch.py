"""Verify intended dispatch independently of setup and filler traffic."""

import re
from urllib.parse import parse_qs


def match_requirements(contract: dict, request: dict) -> list[str]:
    """Match transient request data before storing redacted dispatch evidence."""
    if request.get("kind") != "scenario":
        return []
    matched = []
    for requirement in contract.get("requirements", []):
        if request.get("method") != requirement["method"]:
            continue
        path = request.get("path", "")
        if "path" in requirement and path != requirement["path"]:
            continue
        if "path_regex" in requirement and not re.fullmatch(
            requirement["path_regex"], path
        ):
            continue
        if (
            "body_exact" in requirement
            and request.get("body", "") != requirement["body_exact"]
        ):
            continue
        if "body_regex" in requirement and not re.search(
            requirement["body_regex"], request.get("body", "")
        ):
            continue
        if "query_regex" in requirement and not re.search(
            requirement["query_regex"], request.get("query", "")
        ):
            continue
        if any(
            request.get("headers", {}).get(name.lower()) != value
            for name, value in requirement.get("headers", {}).items()
        ):
            continue
        matched.append(requirement["id"])
    return matched


def verify_requirements(contract: dict, events: list[dict]) -> dict:
    """Require every declared action's observed dispatch count."""
    checks = []
    for requirement in contract["requirements"]:
        observed = sum(
            event.get("kind") == "scenario"
            and requirement["id"] in event.get("matched_requirements", [])
            for event in events
        )
        checks.append(
            {
                "id": requirement["id"],
                "observed": observed,
                "required": requirement["minimum_dispatches"],
                "payload_class": requirement["payload_class"],
                "passed": observed >= requirement["minimum_dispatches"],
            }
        )
    return {
        "passed": bool(checks) and all(check["passed"] for check in checks),
        "requirements": checks,
    }


def verify_dispatch(contract: dict, events: list[dict]) -> dict:
    """Count only observed actions matching the declared dispatch contract."""
    if "requirements" in contract:
        return verify_requirements(contract, events)
    matched = []
    for event in events:
        if (
            event.get("kind") != "scenario"
            or event.get("method") != contract["method"]
            or event.get("path") != contract["path"]
        ):
            continue
        values = parse_qs(event.get("query", ""), keep_blank_values=True).get(
            contract["parameter"], []
        )
        if not values or not any(values):
            continue
        expected = contract.get("payloads")
        if expected is not None and values[0] not in expected:
            continue
        matched.append(event)
    observed = (
        len(
            {
                parse_qs(event.get("query", ""))[contract["parameter"]][0]
                for event in matched
            }
        )
        if "payloads" in contract
        else len(matched)
    )
    return {
        "passed": observed >= contract["minimum_dispatches"],
        "observed": observed,
        "required": contract["minimum_dispatches"],
        "payload_class": contract["payload_class"],
    }
