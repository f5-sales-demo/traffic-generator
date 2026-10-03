"""Browser route actions cannot be replaced by static HTML request counts."""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
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
