"""Observed tool actions require intended invocation, verified binary and successful completion."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_dispatch import verify_tool_actions
from traffic_runtime import scenario_action_verification
from traffic_tool import attributed_arguments, native_binary


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


def test_child_tool_marker_preserves_authentication_header():
    args = [
        "-u",
        "https://www.example.test/vampi/users/v1",
        "--headers=Authorization: Bearer synthetic",
    ]
    encoded = attributed_arguments("sqlmap", args, "child-opaque")
    assert (
        "--headers=Authorization: Bearer synthetic\nX-TGen-Child: child-opaque"
        in encoded
    )
    assert args[-1] == "--headers=Authorization: Bearer synthetic"
    assert attributed_arguments("curl", ["--data", "synthetic"], "child-opaque")[
        -2:
    ] == ["-H", "X-TGen-Child: child-opaque"]


def test_native_tool_resolution_skips_owned_wrapper_chain(tmp_path):
    runtime = tmp_path / "runtime"
    wrappers = runtime / "pass-active" / "parent" / "tool-bin"
    wrappers.mkdir(parents=True)
    native = tmp_path / "native"
    native.mkdir()
    for folder in (wrappers, native):
        binary = folder / "curl"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o700)
    assert native_binary("curl", str(wrappers) + ":" + str(native), runtime) == str(
        native / "curl"
    )


def test_zap_child_replacer_configuration_preserves_native_arguments():
    args = ["-daemon", "-config", "api.disablekey=true"]
    result = attributed_arguments("zap", args, "child-opaque")
    assert result[: len(args)] == args
    assert "replacer.full_list(0).matchstr=X-TGen-Child" in result
    assert "replacer.full_list(0).replacement=child-opaque" in result


def test_failed_scanner_cannot_keep_aggregate_dispatch_acceptance(tmp_path):
    result = {"outcome": "tool_failure", "dispatch_contract_verified": True}
    scenario_action_verification(tmp_path, {"id": "scanner", "budget": "http"}, result)
    assert not result["dispatch_contract_verified"]
