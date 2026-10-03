"""Verify intended dispatch independently of setup and filler traffic."""

import json
import re
from urllib.parse import parse_qs

SUCCESS_MIN, SUCCESS_MAX = 200, 300


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
        if "graphql_operation" in requirement:
            try:
                document = json.loads(request.get("body", ""))
            except ValueError:
                continue
            if not isinstance(document, dict) or not re.search(
                requirement["graphql_operation"], document.get("query", "")
            ):
                continue
        if "json_body_type" in requirement:
            try:
                document = json.loads(request.get("body", ""))
            except ValueError:
                continue
            if requirement["json_body_type"] == "array" and not isinstance(
                document, list
            ):
                continue
            if (
                "json_array_min" in requirement
                and len(document) < requirement["json_array_min"]
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


def validate_dispatch_contract(contract: dict) -> None:
    """Reject assertions that cannot identify a concrete request action."""
    identifiers = set()
    for requirement in contract.get("requirements", []):
        if requirement.get("id") in identifiers or not requirement.get("id"):
            message = "dispatch requirement identifiers must be unique"
            raise ValueError(message)
        identifiers.add(requirement["id"])
        if (
            not requirement.get("method")
            or not (requirement.get("path") or requirement.get("path_regex"))
            or not requirement.get("payload_class")
            or requirement.get("minimum_dispatches", 0) <= 0
        ):
            message = (
                "dispatch requirement must identify method endpoint payload and count"
            )
            raise ValueError(message)
        for field in ("path_regex", "body_regex", "query_regex", "graphql_operation"):
            if field in requirement:
                re.compile(requirement[field])
    if "requirements" in contract and not identifiers:
        message = "dispatch contract requires at least one action"
        raise ValueError(message)


def classify_outcome(event: dict) -> str:
    """Keep observed HTTP outcomes distinct from attributed WAAP controls."""
    if event.get("transport_error"):
        return "transport_failure"
    status = event.get("status")
    if status in (403, 429):
        return "mitigation_candidate"
    if status in event.get("expected_statuses", []):
        return "expected_application_response"
    if isinstance(status, int) and SUCCESS_MIN <= status < SUCCESS_MAX:
        return "application_response"
    return "unexpected_application_response"
