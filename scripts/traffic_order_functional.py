"""Require concrete native order mutations and exact journal restoration."""

import json
from pathlib import Path

ORDER_PAYLOAD_COUNT = 3
ORDER_MUTATED_QUANTITY = 100


def verify_order_mutation(scenario: dict, result: dict, directory: Path) -> dict:
    """Require native changed order fields and exact host-journaled credit restoration."""
    functional = json.loads((directory / "order-functional.json").read_text())
    baseline = json.loads((directory / "order-baseline.json").read_text())
    recovery = json.loads((directory / "order-restoration.json").read_text())
    attempts = functional.get("attempts", [])
    return {
        "passed": functional.get("passed") is True
        and functional.get("source_commit") == result.get("source_commit")
        and functional.get("artifact_sha256") == result.get("artifact_sha256")
        and len(attempts) == ORDER_PAYLOAD_COUNT
        and attempts[0].get("response", {}).get("status") == "returned"
        and attempts[0].get("response", {}).get("quantity") == ORDER_MUTATED_QUANTITY
        and all(row.get("response") == row.get("readback") for row in attempts)
        and recovery.get("restored") is True
        and recovery.get("before") == recovery.get("after") == baseline.get("before")
        and result.get("order_restoration") is True
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True,
        "behavior": scenario["functional_contract"]["behavior"],
    }
