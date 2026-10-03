"""Static mappings cannot establish coverage without verified current-pass evidence."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_report import build_report


def test_failed_missing_and_stale_source_dependencies_fail_report(tmp_path):
    child = tmp_path / "suite--action"
    child.mkdir()
    receipt = {
        "id": "suite/action",
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "source_sha256": "a" * 64,
    }
    (child / "receipt.json").write_text(json.dumps(receipt))
    report = build_report(tmp_path, ["suite/action"])
    assert report["passed"]
    assert report["dependencies"][0]["receipt_sha256"]
    assert not build_report(tmp_path, ["suite/missing"])["passed"]
    receipt["outcome"] = "tool_failure"
    (child / "receipt.json").write_text(json.dumps(receipt))
    assert not build_report(tmp_path, ["suite/action"])["passed"]
