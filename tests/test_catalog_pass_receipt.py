"""Catalog completeness binds exact scenarios, source and artifact provenance."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from catalog_pass_receipt import catalog_pass_receipt, pass_traffic


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


def test_pass_traffic_uses_deltas_and_rejects_bad_accounting():
    before = {
        "elapsed": 1000,
        "benign_requests": 180000,
        "attack_requests": 20000,
        "benign_completed": 180000,
        "benign_success": 180000,
        "benign_transport_failures": 0,
        "attack_transport_failures": 0,
    }
    after = {
        "elapsed": 1100,
        "benign_requests": 198000,
        "attack_requests": 22000,
        "benign_completed": 198000,
        "benign_success": 198000,
        "benign_transport_failures": 0,
        "attack_transport_failures": 0,
    }
    result = pass_traffic(before, after)
    assert result["verified"]
    assert result["aggregate_http_rps"] == 200
    assert result["duration_seconds"] == 100
    for key, value in (
        ("elapsed", 1000),
        ("attack_requests", 20000),
        ("benign_success", 197000),
        ("benign_transport_failures", 1),
        ("attack_transport_failures", 1),
        ("benign_requests", None),
    ):
        assert not pass_traffic(before, {**after, key: value})["verified"]


def test_full_catalog_without_pass_metrics_cannot_be_accepted():
    config = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    expected = {f"suite/{i}": "c" * 64 for i in range(164)}
    receipts = [
        {
            "id": identifier,
            "source_sha256": digest,
            **config,
            "outcome": "launched",
            "dispatch_contract_verified": True,
            "functional_verified": True,
            "transport_failures": 0,
            "tool_cancellations": 0,
        }
        for identifier, digest in expected.items()
    ]
    result = catalog_pass_receipt("pass-test", 1, receipts, expected, expected, config)
    assert result["catalog_complete"]
    assert not result["catalog_accepted"]
    result = catalog_pass_receipt(
        "pass-test", 1, receipts, expected, expected, config, {"verified": True}
    )
    assert result["catalog_accepted"]
