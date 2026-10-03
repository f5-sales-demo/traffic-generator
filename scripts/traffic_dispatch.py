"""Verify intended dispatch independently of setup and filler traffic."""

import json
import re
from urllib.parse import parse_qs

from traffic_connections import tls_matrix

SUCCESS_MIN, SUCCESS_MAX = 200, 300


def structured_body_matches(requirement: dict, body: str) -> bool:
    """Check GraphQL operation and batch shape after strict JSON decoding."""
    if "graphql_operation" not in requirement and "json_body_type" not in requirement:
        return True
    try:
        document = json.loads(body)
    except ValueError:
        return False
    if "graphql_operation" in requirement:
        return isinstance(document, dict) and bool(
            re.search(requirement["graphql_operation"], document.get("query", ""))
        )
    if requirement["json_body_type"] == "array":
        return isinstance(document, list) and len(document) >= requirement.get(
            "json_array_min", 0
        )
    return False


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
        if any(
            not re.search(pattern, request.get("headers", {}).get(name.lower(), ""))
            for name, pattern in requirement.get("header_regex", {}).items()
        ):
            continue
        if any(
            request.get("headers", {}).get(name.lower())
            for name in requirement.get("absent_headers", [])
        ):
            continue
        if not structured_body_matches(requirement, request.get("body", "")):
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


def verify_browser_actions(contract: dict, receipt: dict) -> dict:
    """Require the manifest's exact browser steps, assertions and cleanup receipt."""
    scenarios = [
        scenario
        for scenario in receipt.get("scenarios", [])
        if scenario.get("name") == contract["scenario"]
    ]
    if len(scenarios) != 1:
        return {"passed": False, "reason": "browser scenario receipt missing"}
    scenario = scenarios[0]
    observed = {step["name"]: step for step in scenario.get("steps", [])}
    checks = [
        {
            "name": name,
            "passed": name in observed
            and observed[name].get("status") == "passed"
            and observed[name].get("assertions", {}).get("status") == "passed"
            and observed[name].get("screenshot", {}).get("captureStatus") == "captured"
            and observed[name].get("screenshot", {}).get("assertionStatus") == "passed",
        }
        for name in contract["steps"]
    ]
    cleanup = receipt.get("cleanup", {})
    passed = (
        bool(checks)
        and all(check["passed"] for check in checks)
        and scenario.get("status") == "passed"
        and cleanup.get("browser") == "closed"
        and not cleanup.get("errors")
    )
    return {"passed": passed, "steps": checks}


def verify_connection_probe(identifier: str, receipt: dict) -> dict:
    """Require the intended protocol offerings or bounded slow-header activity."""
    results = receipt.get("results", [])
    checks = {
        "identity": receipt.get("scenario") == identifier,
        "attempt_count": receipt.get("attempts") == len(results) and bool(results),
        "rate": 0 < receipt.get("attempt_limit_per_second", 0) <= 20,
        "transport": not any(result.get("transport_failure") for result in results),
        "cleanup": receipt.get("connections_closed") is True,
    }
    if "slowloris" in identifier:
        count = receipt.get("maximum_slow_connections", 0)
        checks["slow_connections"] = 0 < count <= 20 and len(results) == count
        checks["partial_headers"] = receipt.get("slow_header_writes", 0) == count * 3
        checks["duration"] = receipt.get("elapsed_seconds", 0) >= 15
    else:
        checks["offerings"] = all(
            any(all(result.get(key) == value for key, value in offering.items()) for result in results)
            for offering in tls_matrix(identifier)
        )
        checks["certificate"] = any(result.get("certificate_validated") for result in results)
        if "ssl-scanning" not in identifier:
            checks["http_port"] = any(result.get("port") == 80 for result in results)
    return {"passed": all(checks.values()), "checks": checks}
