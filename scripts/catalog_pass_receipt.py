"""Exact source-bound catalog dispatch and native functional acceptance."""

import time


def catalog_pass_receipt(
    pass_id: str,
    started: float,
    receipts: list[dict],
    expected: dict,
    catalog: dict,
    config: dict,
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
        "catalog_accepted": catalog_complete and functional,
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
