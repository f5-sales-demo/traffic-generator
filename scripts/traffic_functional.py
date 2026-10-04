"""Functional acceptance from source contracts and observed native responses."""

import hashlib
import json
from itertools import pairwise
from pathlib import Path

from traffic_csd_functional import verify_csd_libraries

CREDENTIAL_COUNT = 15
CONNECTION_LIMIT = 20


def verify_credentials(scenario: dict, result: dict, directory: Path) -> dict:
    """Inspect native browser outcomes, exact credential count, and closed sessions."""
    path = directory / "credential-functional.json"
    try:
        evidence = json.loads(path.read_text()) if path.exists() else {}
    except (OSError, ValueError):
        return {"passed": False, "reason": "native credential evidence unreadable"}
    if not isinstance(evidence, dict):
        return {
            "passed": False,
            "reason": "native credential evidence is not an object",
        }
    attempts = evidence.get("attempts", [])
    if not isinstance(attempts, list) or any(not isinstance(a, dict) for a in attempts):
        return {"passed": False, "reason": "native credential attempts malformed"}
    screenshots = evidence.get("screenshots", [])
    if not isinstance(screenshots, list) or any(
        not isinstance(name, str) for name in screenshots
    ):
        return {"passed": False, "reason": "native credential screenshots malformed"}
    passed = (
        evidence.get("scenario") == scenario["id"]
        and evidence.get("source_commit") == result.get("source_commit")
        and evidence.get("passed") is True
        and evidence.get("contextsClosed") is True
        and evidence.get("browserErrors") == []
        and len(attempts) == CREDENTIAL_COUNT
        and [attempt.get("index") for attempt in attempts]
        == list(range(CREDENTIAL_COUNT))
        and all(
            attempt.get("passed") is True
            and attempt.get("sessionClosed") is True
            and attempt.get("expectedAccepted") is (attempt["index"] == 0)
            and (
                attempt.get("accepted") is True
                if attempt["index"] == 0
                else attempt.get("rejected") is True
            )
            for attempt in attempts
        )
        and len(evidence.get("screenshots", [])) == CREDENTIAL_COUNT
        and all(
            Path(name).name == name
            and (directory / name).is_file()
            and (directory / name)
            .read_bytes()
            .startswith(bytes.fromhex("89504e470d0a1a0a"))
            for name in evidence.get("screenshots", [])
        )
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0
    )
    return {
        "passed": passed,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_attempts": len(attempts),
        "screenshots": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in evidence.get("screenshots", [])
            if Path(name).name == name and (directory / name).is_file()
        },
        "evidence": path.name,
        "control_attribution": "separate WAAP evidence required",
    }


def verify_slow_headers(scenario: dict, result: dict, directory: Path) -> dict:
    """Require paced native partial headers, observed rounds, and closed sockets."""
    path = directory / "connections.json"
    receipt = json.loads(path.read_text()) if path.exists() else {}
    probes = receipt.get("results", [])
    attempts = [probe.get("attempted_monotonic") for probe in probes]
    rate = receipt.get("attempt_limit_per_second", 0)
    spacing = (
        0 < rate <= CONNECTION_LIMIT
        and bool(attempts)
        and all(isinstance(value, (int, float)) for value in attempts)
    )
    spacing = spacing and all(
        later - earlier >= 1 / rate - 0.001 for earlier, later in pairwise(attempts)
    )
    return {
        "passed": receipt.get("execution") == "native bounded socket probe"
        and receipt.get("scenario") == scenario["id"]
        and spacing
        and all(probe.get("partial_headers_sent") is True for probe in probes)
        and result.get("connection_probe", {}).get("passed") is True
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "observed_attempt_spacing": spacing,
        "claim": "native slow-header connection behavior; control attribution separate",
    }


def verify_commands(scenario: dict, result: dict, directory: Path) -> dict:
    """Require every declared native command response, not only payload dispatch."""
    path = directory / "command-functional.jsonl"
    rows = (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )
    required = len(scenario["dispatch_contract"]["requirements"])
    return {
        "passed": len(rows) == required
        and all(row.get("passed") is True for row in rows)
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_outcomes": len(rows),
        "control_attribution": "separate WAAP evidence required",
    }


def verify_functional(
    scenario: dict, result: dict, responses: list[dict], directory: Path
) -> dict:
    """Require explicit scope, content assertions, and complete native outcomes."""
    contract = scenario.get("functional_contract", {})
    if (
        contract.get("verifier") == "native-dvwa-credentials"
        and scenario["id"] == "bot-simulation/01-playwright-credential-stuff"
    ):
        return verify_credentials(scenario, result, directory)
    if contract.get("verifier") == "native-csd-libraries":
        return verify_csd_libraries(scenario, result, directory)
    if (
        contract.get("verifier") == "native-slow-headers"
        and scenario["id"] == "traffic-generation/02-slowloris"
    ):
        return verify_slow_headers(scenario, result, directory)
    if (
        contract.get("verifier") == "native-dvwa-command"
        and scenario["id"] == "dvwa-exploits/02-command-injection"
    ):
        return verify_commands(scenario, result, directory)
    requirements = scenario.get("dispatch_contract", {}).get("requirements", [])
    declared = contract.get("native_response_requirements", [])
    checks = [
        {
            "id": "direct-native-api",
            "passed": scenario.get("kind") == "shell"
            and not scenario.get("adapter")
            and not any(
                key in scenario
                for key in (
                    "tool_contract",
                    "nested_contract",
                    "workload_contract",
                    "browser_contract",
                    "fixture_contract",
                )
            ),
        },
        {"id": "declared-functional-scope", "passed": bool(contract.get("behavior"))},
        {
            "id": "read-only-scope",
            "passed": contract.get("mutation_policy") == "read-only"
            and bool(requirements)
            and all(r["method"] in ("GET", "HEAD") for r in requirements),
        },
        {
            "id": "complete-action-contract",
            "passed": bool(declared)
            and set(declared) == {r["id"] for r in requirements},
        },
        {
            "id": "successful-execution",
            "passed": result.get("outcome") == "launched"
            and result.get("dispatch_contract_verified") is True,
        },
        {
            "id": "zero-transport-failures",
            "passed": result.get("transport_failures") == 0
            and result.get("tool_cancellations") == 0,
        },
    ]
    for requirement in requirements:
        identifier = requirement["id"]
        events = [
            e
            for e in responses
            if e.get("scenario") == scenario["id"]
            and e.get("kind") == "scenario"
            and identifier in e.get("matched_requirements", [])
        ]
        specification = requirement.get("response_contract", {})
        content_declared = bool(specification.get("content_type")) and any(
            specification.get(key)
            for key in (
                "text_contains",
                "json_equals",
                "json_keys",
                "json_nonempty_lists",
                "json_document_equals",
                "graphql_data_field",
                "graphql_response_fields",
            )
        )
        checks.append(
            {
                "id": identifier,
                "observed": len(events),
                "passed": identifier in declared
                and content_declared
                and len(events) >= requirement.get("minimum_dispatches", 1)
                and all(
                    e.get("upstream_dispatched") is True
                    and not e.get("transport_error")
                    and e.get("status") in requirement.get("expected_statuses", [])
                    and e.get("response_assertions", {}).get(identifier) is True
                    for e in events
                ),
            }
        )
    return {
        "passed": all(check["passed"] for check in checks),
        "behavior": contract.get("behavior"),
        "checks": checks,
        "control_attribution": "separate WAAP evidence required",
    }
