"""Exact source-bound catalog dispatch and native functional acceptance."""

import math
import time

MIN_HTTP_RPS = 190
MAX_HTTP_RPS = 210
MIN_BENIGN_SUCCESS = 0.99
EXPECTED_CATALOG_ENTRIES = 164


def pass_traffic(before: dict, after: dict) -> dict:
    """Use counter deltas for this pass; reject missing or decreasing accounting."""
    keys = (
        "elapsed",
        "benign_requests",
        "attack_requests",
        "benign_completed",
        "benign_success",
        "benign_transport_failures",
        "attack_transport_failures",
    )
    if any(
        isinstance(point.get(key), bool)
        or not isinstance(point.get(key), (int, float))
        or not math.isfinite(point[key])
        for point in (before, after)
        for key in keys
    ):
        return {"verified": False, "reason": "missing or malformed pass metrics"}
    delta = {key: after[key] - before[key] for key in keys}
    if (
        any(value < 0 for value in delta.values())
        or delta["elapsed"] <= 0
        or delta["benign_completed"] <= 0
    ):
        return {"verified": False, "reason": "pass metrics reset or empty"}
    rate = (delta["benign_requests"] + delta["attack_requests"]) / delta["elapsed"]
    success = delta["benign_success"] / delta["benign_completed"]
    return {
        "verified": (
            MIN_HTTP_RPS <= rate <= MAX_HTTP_RPS
            and MIN_BENIGN_SUCCESS <= success <= 1
            and delta["benign_transport_failures"] == 0
            and delta["attack_transport_failures"] == 0
        ),
        "aggregate_http_rps": rate,
        "benign_success": success,
        "duration_seconds": delta["elapsed"],
        "baseline_transport_failures": delta["benign_transport_failures"],
        "attack_transport_failures": delta["attack_transport_failures"],
        "counts": delta,
    }


def catalog_pass_receipt(
    pass_id: str,
    started: float,
    receipts: list[dict],
    expected: dict,
    catalog: dict,
    config: dict,
    traffic: dict | None = None,
) -> dict:
    """Bind exact scenario identity, source and terminal execution to a complete pass."""
    observed = {receipt.get("id"): receipt for receipt in receipts}
    complete = len(receipts) == len(observed) and set(observed) == set(expected)
    verified = complete and all(
        receipt.get("source_sha256") == expected[identifier]
        and receipt.get("source_commit") == config["source_commit"]
        and receipt.get("artifact_sha256") == config["artifact_sha256"]
        and receipt.get("outcome") == "launched"
        and receipt.get("dispatch_contract_verified") is True
        and not receipt.get("transport_failures", 0)
        and not receipt.get("tool_cancellations", 0)
        for identifier, receipt in observed.items()
    )
    catalog_complete = complete and set(expected) == set(catalog)
    functional = verified and all(
        receipt.get("functional_verified") is True for receipt in receipts
    )
    return {
        "id": pass_id,
        "started": started,
        "completed": time.time(),
        "source_commit": config["source_commit"],
        "artifact_sha256": config["artifact_sha256"],
        "complete": complete,
        "catalog_complete": catalog_complete,
        "catalog_accepted": catalog_complete
        and functional
        and len(catalog) == EXPECTED_CATALOG_ENTRIES
        and bool(traffic and traffic.get("verified")),
        "traffic": traffic
        or {"verified": False, "reason": "pass traffic evidence missing"},
        "functional_verified": functional,
        "functional_gaps": [
            receipt.get("id")
            for receipt in receipts
            if receipt.get("functional_verified") is not True
        ],
        "claim": "observed dispatch is separate from native functional acceptance",
        "passed": verified,
        "scenario_count": len(receipts),
        "scenarios": receipts,
    }
