"""Catalog completeness binds exact scenarios, source and artifact provenance."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_runtime import catalog_pass_receipt


def test_full_pass_rejects_duplicate_stale_and_missing_action_evidence():
    config = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    expected = {"suite/one": "c" * 64, "suite/two": "d" * 64}
    valid = [
        {
            "id": identifier,
            "source_sha256": digest,
            **config,
            "outcome": "launched",
            "dispatch_contract_verified": True,
            "transport_failures": 0,
            "tool_cancellations": 0,
        }
        for identifier, digest in expected.items()
    ]
    assert catalog_pass_receipt("pass-test", 1, valid, expected, expected, config)[
        "passed"
    ]
    for receipts in [
        valid[:1],
        [valid[0], valid[0]],
        [dict(valid[0], source_commit="e" * 40), valid[1]],
        [dict(valid[0], source_sha256="e" * 64), valid[1]],
        [dict(valid[0], artifact_sha256="e" * 64), valid[1]],
        [dict(valid[0], dispatch_contract_verified=False), valid[1]],
        [dict(valid[0], tool_cancellations=1), valid[1]],
        [dict(valid[0], transport_failures=1), valid[1]],
    ]:
        assert not catalog_pass_receipt(
            "pass-test", 1, receipts, expected, expected, config
        )["passed"]


def test_suite_slice_cannot_establish_catalog_acceptance():
    config = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    expected = {"suite/one": "c" * 64, "suite/two": "d" * 64}
    receipt = {
        "id": "suite/one",
        "source_sha256": "c" * 64,
        **config,
        "outcome": "launched",
        "dispatch_contract_verified": True,
    }
    result = catalog_pass_receipt(
        "pass-test", 1, [receipt], {"suite/one": "c" * 64}, expected, config
    )
    assert result["passed"]
    assert not result["catalog_complete"]
    assert not result["catalog_accepted"]
