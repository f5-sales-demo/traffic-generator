"""Browser route actions cannot be replaced by static HTML request counts."""

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import traffic_runtime as runtime
from traffic_dispatch import verify_route_actions


def test_every_fragment_payload_requires_rendered_route_action():
    contract = {"actions": ["fragment-0", "fragment-1"]}
    receipt: dict[str, Any] = {
        "actions": [{"id": "fragment-0", "performed": True, "rendered": True}],
        "browser_closed": True,
    }
    assert not verify_route_actions(contract, receipt)["passed"]
    receipt["actions"].append({"id": "fragment-1", "performed": True, "rendered": True})
    assert verify_route_actions(contract, receipt)["passed"]
    receipt["browser_closed"] = False
    assert not verify_route_actions(contract, receipt)["passed"]


def test_browser_action_cannot_override_failed_response_assertions(tmp_path):
    """A performed action cannot turn an unexpected server failure into coverage."""
    scenario = {
        "dispatch_contract": {
            "requirements": [
                {
                    "id": "navigate",
                    "method": "GET",
                    "path": "/juice-shop/",
                    "minimum_dispatches": 1,
                    "payload_class": "navigation",
                    "expected_statuses": [200],
                }
            ]
        },
        "browser_contract": {"steps": []},
        "budget": "http",
    }
    (tmp_path / "dispatch-events.jsonl").write_text(
        json.dumps(
            {
                "kind": "scenario",
                "phase": "execution",
                "matched_requirements": ["navigate"],
                "method": "GET",
                "path": "/juice-shop/",
            }
        )
        + "\n"
    )
    (tmp_path / "response-events.jsonl").write_text(
        json.dumps(
            {"kind": "scenario", "status": 500, "matched_requirements": ["navigate"]}
        )
        + "\n"
    )
    result = {"outcome": "launched", "dispatch_contract_verified": False}
    with patch.object(runtime, "browser_action_receipt", return_value={"passed": True}):
        runtime.scenario_action_verification(tmp_path, scenario, result)
    assert result["intended_dispatch"]["passed"]
    assert not result["response_assertions"]["passed"]
    assert not result["dispatch_contract_verified"]
    assert result["outcome"] == "fixture_failure"


def test_explicit_mitigated_navigation_is_distinct_from_rendered_content():
    contract = {"actions": ["navigate"], "allow_mitigation": True}
    receipt = {
        "actions": [
            {
                "id": "navigate",
                "performed": True,
                "rendered": False,
                "mitigated": True,
                "status": 403,
            }
        ],
        "browser_closed": True,
    }
    assert verify_route_actions(contract, receipt)["passed"]
    assert not verify_route_actions({"actions": ["navigate"]}, receipt)["passed"]
    receipt["actions"][0]["status"] = 500
    assert not verify_route_actions(contract, receipt)["passed"]
