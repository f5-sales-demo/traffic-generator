"""Nested launch success cannot pass without child action verification."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import traffic_runtime as runtime
from traffic_attribution import child_metadata
from traffic_report import build_report


@pytest.fixture(autouse=True)
def inherited_boundary(monkeypatch):
    boundary = Mock()
    boundary.environment.side_effect = lambda _scenario, _domain, directory: {
        **os.environ,
        "TGEN_RESULTS_DIR": str(directory),
    }
    monkeypatch.setattr(runtime.InheritedBoundary, "inherited", lambda _root: boundary)
    return boundary


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


def test_nested_parent_rejects_verified_receipt_from_stale_source(tmp_path):
    """Child receipts must belong to the installed parent's current catalog source."""
    identifier = "bot-simulation/04-rapid-browsing"
    child = tmp_path / "nested-bot-simulation" / identifier.replace("/", "--")
    child.mkdir(parents=True)
    (child / "receipt.json").write_text(
        json.dumps(
            {
                "id": identifier,
                "outcome": "launched",
                "dispatch_contract_verified": True,
                "functional_verified": True,
                "source_sha256": "0" * 64,
            }
        )
    )
    result = {"outcome": "launched", "dispatch_contract_verified": True}
    runtime.nested_action_verification(
        tmp_path, {"nested_contract": {"bot-simulation": [identifier]}}, result
    )
    assert not result["dispatch_contract_verified"]
    assert result["outcome"] == "tool_failure"


def test_retention_removes_only_orphaned_owned_child_markers(tmp_path):
    active = tmp_path / "pass-active"
    active.mkdir()
    child = active / "child"
    child.mkdir()
    markers = tmp_path / "children"
    markers.mkdir()
    for name, destination in (
        ("live", child),
        ("stale", tmp_path / "pass-gone" / "child"),
        ("foreign", tmp_path.parent / "unrelated"),
    ):
        (markers / (name + ".json")).write_text(
            json.dumps({"dispatch_path": str(destination / "dispatch-events.jsonl")})
        )
    runtime.retain(tmp_path, active, 7, 100000)
    assert (markers / "live.json").exists()
    assert not (markers / "stale.json").exists()
    assert (markers / "foreign.json").exists()


def test_nested_child_records_functional_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("TARGET_FQDN", "www.example.test")
    monkeypatch.setenv("TGEN_RUNTIME_DIR", str(tmp_path))
    scenario = {
        "id": "synthetic/action",
        "entrypoint": "scripts/traffic_dispatch.py",
        "kind": "shell",
        "budget": "http",
        "timeout_seconds": 1,
    }

    def dispatched(_directory, _scenario, result):
        result["dispatch_contract_verified"] = True

    with (
        patch.object(runtime, "execute", return_value={"outcome": "launched"}),
        patch.object(runtime, "scenario_action_verification", side_effect=dispatched),
        patch.object(runtime, "verify_functional", return_value={"passed": False}),
    ):
        assert runtime.run_nested(Path(__file__).resolve().parents[1], [scenario]) == 1
    receipt = json.loads((tmp_path / "synthetic--action/receipt.json").read_text())
    assert receipt["functional_verified"] is False
    assert receipt["functional_acceptance"]["passed"] is False


def test_nested_order_command_uses_its_own_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("TARGET_FQDN", "www.example.test")
    monkeypatch.setenv("TGEN_RUNTIME_DIR", str(tmp_path))
    scenario = {
        "id": "synthetic/order",
        "entrypoint": "scripts/traffic_dispatch.py",
        "kind": "shell",
        "budget": "http",
        "timeout_seconds": 1,
        "adapter": "native-order-mutation",
    }
    commands = []

    def execute(command, _log, environment, _timeout):
        commands.append((command, environment["TGEN_RESULTS_DIR"]))
        return {"outcome": "launched"}

    with (
        patch.object(runtime, "execute", side_effect=execute),
        patch.object(runtime, "scenario_action_verification"),
        patch.object(runtime, "verify_functional", return_value={"passed": True}),
    ):
        runtime.run_nested(Path(__file__).resolve().parents[1], [scenario])
    assert commands[0][0][-1] == commands[0][1] == str(tmp_path / "synthetic--order")


def test_nested_refreshes_before_execution_and_recovers_signup(
    tmp_path, monkeypatch, inherited_boundary
):
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("TARGET_FQDN", "www.example.test")
    monkeypatch.setenv("TGEN_RUNTIME_DIR", str(tmp_path))
    scenario = {
        "id": "synthetic/signup",
        "entrypoint": "scripts/traffic_dispatch.py",
        "kind": "shell",
        "budget": "http",
        "timeout_seconds": 1,
        "fixture_refresh": ["crapi"],
        "fixture_contract": {"restore_signup": True},
    }
    calls = []
    inherited_boundary.refresh_fixtures.side_effect = lambda *_: calls.append("refresh")

    def recover_signup(*_):
        calls.append("recover")
        return True

    inherited_boundary.recover_signup.side_effect = recover_signup

    def execute(*_):
        calls.append("execute")
        return {"outcome": "launched"}

    with (
        patch.object(runtime, "execute", side_effect=execute),
        patch.object(runtime, "scenario_action_verification"),
        patch.object(runtime, "verify_functional", return_value={"passed": True}),
    ):
        assert runtime.run_nested(Path(__file__).parents[1], [scenario]) == 0
    assert calls == ["refresh", "execute", "recover"]
    receipt = json.loads((tmp_path / "synthetic--signup/receipt.json").read_text())
    assert receipt["signup_restoration"] is True


def test_missing_native_artifact_retains_failed_child_receipt(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("TARGET_FQDN", "www.example.test")
    monkeypatch.setenv("TGEN_RUNTIME_DIR", str(tmp_path))
    scenario = {
        "id": "synthetic/missing",
        "entrypoint": "scripts/traffic_dispatch.py",
        "kind": "shell",
        "budget": "http",
        "timeout_seconds": 1,
    }
    with (
        patch.object(runtime, "execute", return_value={"outcome": "launched"}),
        patch.object(runtime, "scenario_action_verification"),
        patch.object(runtime, "verify_functional", side_effect=FileNotFoundError),
    ):
        assert runtime.run_nested(Path(__file__).parents[1], [scenario]) == 1
    receipt = json.loads((tmp_path / "synthetic--missing/receipt.json").read_text())
    assert not receipt["functional_verified"]
    assert receipt["outcome"] == "fixture_failure"
