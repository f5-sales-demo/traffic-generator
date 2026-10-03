"""Observed dispatch and prerequisite failures must drive scenario receipts."""

import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
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
            config={"results_dir": temporary, "scenario_timeout_seconds": 10},
            refresh_fixtures=lambda _: (_ for _ in ()).throw(
                ValueError("private fixture material")
            ),
        )
        state = {"failures": []}
        result = runtime._scenario(
            ROOT,
            scenario(),
            "www.example.test",
            active,
            boundary,
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
            config={"results_dir": temporary, "scenario_timeout_seconds": 10},
            refresh_fixtures=lambda _: None,
            environment=lambda *_: {},
            metrics=lambda: {"scenario_requests": 1},
            wrap=lambda command, **_options: command,
        )
        with (
            patch.object(runtime, "execute", return_value={"outcome": "launched"}),
            patch.object(runtime, "evidence_monitor", return_value=lambda: None),
        ):
            result = runtime._scenario(
                ROOT,
                scenario(),
                "www.example.test",
                active,
                boundary,
                {"failures": []},
                threading.Event(),
            )
        assert result["outcome"] == "fixture_failure"
        assert not result["dispatch_contract_verified"]
