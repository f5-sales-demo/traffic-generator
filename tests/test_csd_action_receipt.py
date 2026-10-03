"""Browser scenario actions require their own successful step assertions and cleanup."""

import sys
from typing import Any
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_dispatch import verify_browser_actions  # noqa: E402
from traffic_runtime import browser_action_receipt  # noqa: E402


def test_failed_or_missing_browser_action_cannot_pass():
    """Network requests alone cannot establish a synthetic browser action."""
    receipt: dict[str, Any] = {
        "scenarios": [
            {
                "name": "fixture",
                "status": "passed",
                "steps": [
                    {
                        "name": "navigate",
                        "status": "passed",
                        "assertions": {"status": "passed"},
                    },
                    {
                        "name": "set-fields",
                        "status": "passed",
                        "assertions": {"status": "passed"},
                        "screenshot": {"status": "passed"},
                    },
                ],
            }
        ],
        "cleanup": {"browser": "closed", "errors": []},
    }
    contract = {"scenario": "fixture", "steps": ["navigate", "set-fields", "cleanup"]}
    assert not verify_browser_actions(contract, receipt)["passed"]
    receipt["scenarios"][0]["steps"].append(
        {
            "name": "cleanup",
            "status": "passed",
            "assertions": {"status": "passed"},
            "screenshot": {"status": "passed"},
        }
    )
    assert verify_browser_actions(contract, receipt)["passed"]
    receipt["scenarios"][0]["steps"][1]["assertions"]["status"] = "failed"
    assert not verify_browser_actions(contract, receipt)["passed"]


def test_browser_cleanup_failure_fails_declared_action():
    """A successful DOM assertion does not excuse an orphaned browser."""
    receipt: dict[str, Any] = {
        "scenarios": [
            {
                "name": "fixture",
                "status": "passed",
                "steps": [
                    {
                        "name": "action",
                        "status": "passed",
                        "assertions": {"status": "passed"},
                    }
                ],
            }
        ],
        "cleanup": {"browser": "failed", "errors": []},
    }
    assert not verify_browser_actions(
        {"scenario": "fixture", "steps": ["action"]}, receipt
    )["passed"]


def test_corrupt_browser_receipt_fails_closed(tmp_path):
    """A broken receipt fails this scenario without aborting the remaining catalog."""
    directory = tmp_path / "browser-run"
    directory.mkdir()
    (directory / "receipt.json").write_text("{interrupted")
    assert not browser_action_receipt(tmp_path, {"scenario": "fixture", "steps": ["action"]})["passed"]
