"""Observed tool actions require intended invocation, verified binary and successful completion."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_dispatch import verify_tool_actions


def test_tool_failure_missing_arguments_and_no_completion_fail():
    contract = {
        "requirements": [
            {"tool": "sqlmap", "argument_regex": "users/v1/login", "minimum": 1}
        ]
    }
    event = {
        "tool": "sqlmap",
        "arguments": ["-u", "https://www.example.test/vampi/users/v1/login"],
        "binary_sha256": "a" * 64,
        "completed": True,
        "exit_code": 0,
    }
    assert verify_tool_actions(contract, [event])["passed"]
    assert not verify_tool_actions(contract, [dict(event, completed=False)])["passed"]
    assert not verify_tool_actions(contract, [dict(event, exit_code=1)])["passed"]
    assert not verify_tool_actions(contract, [dict(event, arguments=["--help"])])[
        "passed"
    ]
