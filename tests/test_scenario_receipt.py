"""Observed dispatch and prerequisite failures must drive scenario receipts."""

import json
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import traffic_runtime as runtime  # noqa: E402


def scenario():
    """A prerequisite-dependent action requires its actual endpoint launch."""
    return {
        "id": "synthetic/action",
        "entrypoint": "scripts/traffic_dispatch.py",
        "kind": "shell",
        "budget": "http",
        "timeout_seconds": 10,
        "expected_outcome": "observed dispatch",
        "dispatch_contract": {
            "requirements": [
                {
                    "id": "action",
                    "method": "POST",
                    "path": "/httpbin/post",
                    "minimum_dispatches": 1,
                    "payload_class": "synthetic",
                }
            ]
        },
    }


def test_failed_prerequisite_is_recorded_without_aborting_remaining_catalog():
    """Fixture failures produce a private receipt instead of terminating the supervisor."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        active = root / "pass-test"
        active.mkdir()
        boundary = SimpleNamespace(
            config={
                "results_dir": temporary,
                "scenario_timeout_seconds": 10,
                "source_commit": "a" * 40,
                "artifact_sha256": "b" * 64,
            },
            refresh_fixtures=lambda *_: (_ for _ in ()).throw(
                ValueError("private fixture material")
            ),
        )
        state: dict = {"failures": []}
        result = runtime._scenario(  # pylint: disable=protected-access
            ROOT,
            scenario(),
            "www.example.test",
            active,
            cast("runtime.NetworkBoundary", boundary),
            state,
            threading.Event(),
        )
        assert result["outcome"] == "fixture_failure"
        assert not result["dispatch_contract_verified"]
        receipt = active / "synthetic--action/receipt.json"
        assert receipt.exists()
        assert "private fixture material" not in receipt.read_text()
        assert state["failures"] == [
            {"id": "synthetic/action", "outcome": "fixture_failure"}
        ]


def test_existing_contract_without_observed_action_cannot_be_verified():
    """Successful process exits do not prove a contract was dispatched."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        active = root / "pass-test"
        active.mkdir()
        boundary = SimpleNamespace(
            config={
                "results_dir": temporary,
                "scenario_timeout_seconds": 10,
                "source_commit": "a" * 40,
                "artifact_sha256": "b" * 64,
            },
            refresh_fixtures=lambda *_: None,
            environment=lambda *_: {},
            metrics=lambda: {"scenario_requests": 1},
            wrap=lambda command, **_options: command,
        )
        with (
            patch.object(runtime, "execute", return_value={"outcome": "launched"}),
            patch.object(runtime, "evidence_monitor", return_value=lambda: None),
        ):
            result = runtime._scenario(  # pylint: disable=protected-access
                ROOT,
                scenario(),
                "www.example.test",
                active,
                cast("runtime.NetworkBoundary", boundary),
                {"failures": []},
                threading.Event(),
            )
        assert result["outcome"] == "fixture_failure"
        assert not result["dispatch_contract_verified"]


def test_cancelled_tool_requests_cannot_establish_success():
    """A timed-out scanner request is not an accepted application rejection."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        active = root / "pass-test"
        active.mkdir()
        snapshots = iter(
            [
                {"scenario_requests": 0, "tool_cancellations": 0},
                {"scenario_requests": 1, "tool_cancellations": 1},
            ]
        )
        boundary = SimpleNamespace(
            config={
                "results_dir": temporary,
                "scenario_timeout_seconds": 10,
                "source_commit": "a" * 40,
                "artifact_sha256": "b" * 64,
            },
            refresh_fixtures=lambda *_: None,
            environment=lambda *_: {},
            metrics=lambda: next(snapshots),
            wrap=lambda command, **_options: command,
        )
        with (
            patch.object(runtime, "execute", return_value={"outcome": "launched"}),
            patch.object(runtime, "evidence_monitor", return_value=lambda: None),
        ):
            result = runtime._scenario(  # pylint: disable=protected-access
                ROOT,
                scenario(),
                "www.example.test",
                active,
                cast("runtime.NetworkBoundary", boundary),
                {"failures": []},
                threading.Event(),
            )  # pylint: disable=protected-access
        assert result["outcome"] == "tool_failure"


def test_scenario_mitigation_count_excludes_filler_and_prerequisites(tmp_path):
    """Aggregate filler counters cannot inflate a scenario's attributed responses."""
    active = tmp_path / "pass-test"
    active.mkdir()
    snapshots = iter(
        [
            {"scenario_requests": 0, "attack_mitigated": 0},
            {"scenario_requests": 1, "attack_mitigated": 999},
        ]
    )
    boundary = SimpleNamespace(
        config={
            "results_dir": str(tmp_path),
            "scenario_timeout_seconds": 10,
            "source_commit": "a" * 40,
            "artifact_sha256": "b" * 64,
        },
        refresh_fixtures=lambda *_: None,
        environment=lambda *_: {},
        metrics=lambda: next(snapshots),
        wrap=lambda command, **_options: command,
    )

    def observed_execution(*_args, **_kwargs):
        directory = active / "synthetic--action"
        (directory / "dispatch-events.jsonl").write_text(
            json.dumps({"kind": "scenario", "matched_requirements": ["action"]}) + "\n"
        )
        (directory / "response-events.jsonl").write_text(
            "\n".join(
                json.dumps(event)
                for event in [
                    {"scenario": "synthetic/action", "kind": "scenario", "status": 403},
                    {
                        "scenario": "synthetic/action",
                        "kind": "prerequisite",
                        "status": 403,
                    },
                    {"scenario": "child/action", "kind": "scenario", "status": 429},
                ]
            )
            + "\n"
        )
        return {"outcome": "launched"}

    with patch.object(runtime, "execute", side_effect=observed_execution):
        result = runtime._scenario(  # pylint: disable=protected-access
            ROOT,
            scenario(),
            "www.example.test",
            active,
            cast("runtime.NetworkBoundary", boundary),
            {"failures": []},
            threading.Event(),
        )
    assert result["mitigated_requests"] == 1
