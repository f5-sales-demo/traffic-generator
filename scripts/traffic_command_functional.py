"""Native command effects and exact request-bound blocking acceptance."""

import json
from pathlib import Path

from traffic_security import attributed_responses

HTTP_FORBIDDEN = 403


def verify_commands(scenario: dict, result: dict, directory: Path) -> dict:
    """Require every declared native command response, not only payload dispatch."""
    path = directory / "command-functional.jsonl"
    rows = (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )
    requirements = scenario["dispatch_contract"]["requirements"]
    responses = attributed_responses(scenario, result, directory)
    blocked = {
        response.get("synthetic_identity"): response
        for response in responses
        if response.get("scenario") == scenario["id"]
        and response.get("kind") == "scenario"
        and response.get("method") == "POST"
        and response.get("path") == "/dvwa/vulnerabilities/exec/"
        and response.get("status") == HTTP_FORBIDDEN
        and response.get("control_attributed") is True
    }
    checks = [
        row.get("passed") is True
        or (
            row.get("mitigation_candidate") is True
            and row.get("synthetic_identity") in blocked
            and blocked[row["synthetic_identity"]].get("response_sha256")
            == row.get("response_sha256")
        )
        for row in rows
    ]
    return {
        "passed": len(rows) == len(requirements)
        and all(checks)
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_outcomes": len(rows),
        "control_attribution": "separate WAAP evidence required",
    }
