"""A stored order mutation needs real readback and exact credit restoration."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_order_functional import verify_order_mutation


def test_order_mutation_requires_real_fields_and_host_baseline(tmp_path):
    before = {"order": {"id": 1, "quantity": 1, "status": "delivered"}, "credit": 100}
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "order_restoration": True,
        "outcome": "launched",
        "dispatch_contract_verified": True,
    }
    rows: list[dict] = [
        {
            "response": {"status": "returned", "quantity": 100},
            "readback": {"status": "returned", "quantity": 100},
        }
        for _ in range(3)
    ]
    for row, status in zip(rows, [200, 200, 400], strict=True):
        row["status"] = status
    functional = {
        "passed": True,
        "source_commit": result["source_commit"],
        "artifact_sha256": result["artifact_sha256"],
        "attempts": rows,
    }
    (tmp_path / "order-functional.json").write_text(json.dumps(functional))
    (tmp_path / "order-baseline.json").write_text(json.dumps({"before": before}))
    recovery = {"restored": True, "before": before, "after": before}
    (tmp_path / "order-restoration.json").write_text(json.dumps(recovery))
    scenario = {"functional_contract": {"behavior": "native order and credit"}}
    assert verify_order_mutation(scenario, result, tmp_path)["passed"]
    recovery["after"] = {"order": before["order"], "credit": 1000}
    (tmp_path / "order-restoration.json").write_text(json.dumps(recovery))
    assert not verify_order_mutation(scenario, result, tmp_path)["passed"]
    rows[0]["response"]["quantity"] = 1
    (tmp_path / "order-functional.json").write_text(json.dumps(functional))
    assert not verify_order_mutation(scenario, result, tmp_path)["passed"]
