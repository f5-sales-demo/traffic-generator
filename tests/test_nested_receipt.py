"""Nested launch success cannot pass without child action verification."""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import traffic_runtime as runtime
from traffic_attribution import child_metadata
from traffic_report import build_report


def test_nested_exit_zero_without_dispatch_is_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("TARGET_FQDN", "www.example.test")
    monkeypatch.setenv("TGEN_RUNTIME_DIR", str(tmp_path))
    scenario = {
        "id": "synthetic/action",
        "entrypoint": "scripts/traffic_dispatch.py",
        "kind": "shell",
        "budget": "http",
        "timeout_seconds": 1,
        "dispatch_contract": {
            "requirements": [
                {
                    "id": "action",
                    "method": "POST",
                    "path": "/httpbin/post",
                    "payload_class": "synthetic",
                    "minimum_dispatches": 1,
                }
            ]
        },
    }
    with patch.object(runtime, "execute", return_value={"outcome": "launched"}):
        assert runtime.run_nested(Path(__file__).resolve().parents[1], [scenario]) == 1


def test_child_marker_cannot_escape_owned_runtime(tmp_path):
    parent = {"id": "parent/workload"}
    assert child_metadata(tmp_path, "../foreign", parent) == parent
    assert child_metadata(tmp_path, "unknown", parent) == parent
    child = tmp_path / "children"
    child.mkdir()
    (child / "opaque-marker.json").write_text(
        '{"id":"suite/action","dispatch_path":"'
        + str(tmp_path / "child-events.jsonl")
        + '"}'
    )
    assert child_metadata(tmp_path, "opaque-marker", parent)["id"] == "suite/action"


def test_parent_stress_requires_every_child_verified_receipt(tmp_path):
    child = tmp_path / "nested-api" / "suite--action"
    child.mkdir(parents=True)
    (child / "receipt.json").write_text(
        '{"id":"suite/action","outcome":"launched","dispatch_contract_verified":false,"source_sha256":"'
        + "a" * 64
        + '"}'
    )
    assert not build_report(tmp_path / "nested-api", ["suite/action"])["passed"]
