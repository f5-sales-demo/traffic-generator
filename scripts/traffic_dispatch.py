"""Verify intended dispatch independently of setup and filler traffic."""

import json
import re
from urllib.parse import parse_qs

from traffic_connections import tls_matrix
from traffic_profile import verify_profile

SUCCESS_MIN, SUCCESS_MAX = 200, 300
SHA256_LENGTH = 64


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
        return (
            isinstance(document, list)
            and len(document) >= requirement.get("json_array_min", 0)
            and (
                "json_array_length" not in requirement
                or len(document) == requirement["json_array_length"]
            )
            and all(
                isinstance(item, dict)
                and isinstance(item.get("query"), str)
                and re.search(
                    requirement.get("graphql_batch_operation", r".*"), item["query"]
                )
                for item in document
            )
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
            "body_hex" in requirement
            and request.get("body_hex") != requirement["body_hex"]
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
        query = parse_qs(request.get("query", ""), keep_blank_values=True)
        if any(
            query.get(name) != [value]
            for name, value in requirement.get("query_values", {}).items()
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


CONNECTION_LIMIT = 20
SLOW_PROBE_SECONDS = 15
SLOW_WRITE_ROUNDS = 3
HTTP_PORT = 80


def slow_write_outcomes(receipt: dict, count: int) -> tuple[bool, int]:
    """Peer TLS closure is an observed probe outcome, not an attributed mitigation."""
    results = receipt.get("results", [])
    if not any("write_events" in result for result in results):
        return receipt.get("slow_header_writes", 0) == count * SLOW_WRITE_ROUNDS, 0
    peer_errors = {
        "SSLEOFError",
        "SSLZeroReturnError",
        "BrokenPipeError",
        "ConnectionResetError",
    }
    complete = all(
        result.get("connected") is True
        and len(result.get("write_events", [])) == SLOW_WRITE_ROUNDS
        and {event.get("round") for event in result["write_events"]} == {0, 1, 2}
        and all(
            event.get("sent") is True or event.get("error_type") in peer_errors
            for event in result["write_events"]
        )
        for result in results
    )
    sent = sum(
        event.get("sent") is True
        for result in results
        for event in result.get("write_events", [])
    )
    closed = sum(
        any(
            event.get("error_type") in peer_errors
            for event in result.get("write_events", [])
        )
        for result in results
    )
    return complete and sent == receipt.get("slow_header_writes"), closed


def verify_connection_probe(identifier: str, receipt: dict) -> dict:
    """Require the intended protocol offerings or bounded slow-header activity."""
    results = receipt.get("results", [])
    checks = {
        "identity": receipt.get("scenario") == identifier,
        "attempt_count": receipt.get("attempts") == len(results) and bool(results),
        "rate": 0 < receipt.get("attempt_limit_per_second", 0) <= CONNECTION_LIMIT,
        "transport": not any(result.get("transport_failure") for result in results),
        "cleanup": receipt.get("connections_closed") is True,
    }
    peer_closed = 0
    if "slowloris" in identifier:
        count = receipt.get("maximum_slow_connections", 0)
        checks["slow_connections"] = (
            0 < count <= CONNECTION_LIMIT and len(results) == count
        )
        checks["partial_headers"], peer_closed = slow_write_outcomes(receipt, count)
        checks["duration"] = receipt.get("elapsed_seconds", 0) >= SLOW_PROBE_SECONDS
    else:
        checks["offerings"] = all(
            any(
                all(result.get(key) == value for key, value in offering.items())
                for result in results
            )
            for offering in tls_matrix(identifier)
        )
        checks["certificate"] = any(
            result.get("certificate_validated") for result in results
        )
        if "ssl-scanning" not in identifier:
            checks["http_port"] = any(
                result.get("port") == HTTP_PORT for result in results
            )
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "peer_closed_connections": peer_closed,
        "claim": "observed bounded slow-header probe; no control attribution"
        if "slowloris" in identifier
        else "observed bounded TLS probe; no control attribution",
    }


def declared_socket_cleanup(path: str, metadata: dict, marker: dict) -> bool:
    """Only a dispatched Socket.IO long poll closing during declared cleanup is expected."""
    query = parse_qs(path.partition("?")[2])
    return (
        path.partition("?")[0] == "/juice-shop/socket.io/"
        and query.get("transport") == ["polling"]
        and bool(query.get("sid"))
        and (
            (metadata.get("id", "").startswith("csd-violations/")
            and marker.get("phase") == "closing-browser")
            or (metadata.get("id") == "bot-simulation/04-rapid-browsing"
            and marker.get("phase") in ("navigating", "closing-browser"))
        )
    )


def verify_route_actions(contract: dict, receipt: dict) -> dict:
    """Require every actual fragment navigation and rendered route, plus cleanup."""
    actions = receipt.get("actions", [])
    observed = {action["id"]: action for action in actions}
    exact_inventory = len(actions) == len(observed) and set(observed) == set(
        contract["actions"]
    )
    checks = [
        {
            "id": identifier,
            "passed": observed.get(identifier, {}).get("performed") is True
            and (
                observed.get(identifier, {}).get("rendered") is True
                or (
                    contract.get("allow_mitigation") is True
                    and observed.get(identifier, {}).get("mitigated") is True
                    and observed.get(identifier, {}).get("status") in (403, 429)
                )
            ),
            "rendered": observed.get(identifier, {}).get("rendered") is True,
            "mitigated": observed.get(identifier, {}).get("mitigated") is True,
        }
        for identifier in contract["actions"]
    ]
    return {
        "passed": bool(checks)
        and exact_inventory
        and all(check["passed"] for check in checks)
        and receipt.get("browser_closed") is True,
        "checks": checks,
    }


def verify_tool_actions(contract: dict, events: list[dict]) -> dict:
    """Verify intended scanner invocation and completion separately from HTTP probes."""
    checks = []
    for requirement in contract["requirements"]:
        observed = sum(
            event.get("tool") == requirement["tool"]
            and event.get("completed") is True
            and event.get("exit_code") == 0
            and len(event.get("binary_sha256", "")) == SHA256_LENGTH
            and (
                requirement.get("id") in event.get("matched_requirements", [])
                if "id" in requirement
                else bool(
                    re.search(
                        requirement["argument_regex"],
                        " ".join(event.get("arguments", [])),
                    )
                )
            )
            for event in events
        )
        checks.append(
            {
                "tool": requirement["tool"],
                "observed": observed,
                "passed": observed >= requirement["minimum"],
            }
        )
    return {
        "passed": bool(checks) and all(check["passed"] for check in checks),
        "checks": checks,
    }


def required_response_lists(document: dict, specification: dict) -> bool:
    """Seeded object lists must contain the fields needed by the declared workflow."""
    return all(
        isinstance(document.get(key), list)
        and bool(document[key])
        and all(
            isinstance(item, dict)
            and all(
                isinstance(item.get(field), str) and item[field].strip()
                for field in fields
            )
            for item in document[key]
        )
        for key, fields in specification.items()
    )


def response_content_matches(contract: dict, content_type: str, body: str) -> bool:
    """Evaluate transient response content and retain only assertion booleans."""
    if content_type.split(";", 1)[0] != contract.get("content_type"):
        return False
    if any(term not in body for term in contract.get("text_contains", [])):
        return False
    if any(
        key in contract for key in ("json_equals", "json_keys", "json_nonempty_lists")
    ):
        try:
            document = json.loads(body)
        except ValueError:
            return False
        if not isinstance(document, dict):
            return False
        return (
            all(
                document.get(key) == value
                for key, value in contract.get("json_equals", {}).items()
            )
            and all(key in document for key in contract.get("json_keys", []))
            and required_response_lists(
                document, contract.get("json_nonempty_lists", {})
            )
        )
    return True


def verify_responses(contract: dict, events: list[dict]) -> dict:
    """Request actions require explicit application outcomes or a mitigation candidate."""
    checks = []
    for requirement in contract.get("requirements", []):
        if "expected_statuses" not in requirement:
            continue
        responses = [
            event
            for event in events
            if event.get("kind") == "scenario"
            and requirement["id"] in event.get("matched_requirements", [])
        ]
        checks.append(
            {
                "id": requirement["id"],
                "passed": len(responses) >= requirement.get("minimum_dispatches", 1)
                and all(
                    not event.get("transport_error")
                    and event.get("status")
                    in [*requirement["expected_statuses"], 403, 429]
                    and (
                        "response_contract" not in requirement
                        or event.get("status") in (403, 429)
                        or event.get("response_assertions", {}).get(requirement["id"])
                        is True
                    )
                    for event in responses
                ),
            }
        )
    if contract.get("reject_unmatched_errors"):
        checks.append(
            {
                "id": "unmatched-server-failures",
                "passed": not any(
                    event.get("kind") == "scenario"
                    and not event.get("matched_requirements")
                    and (
                        event.get("transport_error")
                        or event.get("status") in (500, 502, 503, 504)
                    )
                    for event in events
                ),
            }
        )
    return {"passed": all(check["passed"] for check in checks), "checks": checks}


def verify_workload(contract: dict, receipt: dict) -> dict:
    """Require each declared concurrency level's completed requests and cleanup."""
    checks = [
        {
            "concurrency": level,
            "passed": any(
                sample.get("concurrency") == level
                and sample.get("requests", 0) >= contract["minimum_requests"]
                and sample.get("transport_failures") == 0
                and sample.get("content_failures", 0) == 0
                and (
                    not contract.get("verify_behavior")
                    or (
                        sample.get("maximum_active") == level
                        and (
                            sample.get("connections_created", 0) <= level
                            if sample.get("persistent")
                            else sample.get("connections_created") == sample["requests"]
                        )
                    )
                )
                for sample in receipt.get("levels", [])
            ),
        }
        for level in contract["levels"]
    ]
    checks.extend(
        {
            "batch": batch,
            "passed": any(
                sample.get("requests") == batch
                and sample.get("transport_failures") == 0
                and sample.get("content_failures", 0) == 0
                for sample in receipt.get("levels", [])
            ),
        }
        for batch in contract.get("batches", [])
    )
    checks.extend(
        {
            "persistent": mode,
            "passed": any(
                sample.get("persistent") is mode
                and sample.get("requests", 0) >= contract["minimum_requests"]
                and sample.get("connections_created")
                == (sample["concurrency"] if mode else sample["requests"])
                and sample.get("transport_failures") == 0
                and sample.get("content_failures", 0) == 0
                for sample in receipt.get("levels", [])
            ),
        }
        for mode in contract.get("connection_modes", [])
    )
    if "minimum_duration" in contract:
        checks.append(
            {
                "duration": True,
                "passed": receipt.get("elapsed", 0) >= contract["minimum_duration"],
            }
        )
    if contract.get("cache_mode") == "dynamic-bypass":
        checks.append(
            {
                "cache": True,
                "passed": bool(receipt.get("levels"))
                and all(
                    sample.get("cache_failures") == 0 for sample in receipt["levels"]
                ),
            }
        )
    if contract.get("resource_profile"):
        checks.append(
            {
                "id": "resource-profile",
                "passed": verify_profile(receipt.get("resource_profile", {})),
            }
        )
    checks.append(
        {
            "id": "all-workload-samples",
            "passed": bool(receipt.get("levels"))
            and all(
                sample.get("transport_failures") == 0
                and sample.get("content_failures", 0) == 0
                for sample in receipt.get("levels", [])
            ),
        }
    )
    return {
        "passed": bool(checks)
        and all(check["passed"] for check in checks)
        and receipt.get("cleanup") is True,
        "checks": checks,
    }
