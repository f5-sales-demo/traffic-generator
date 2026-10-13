"""Observed tool actions require intended invocation, verified binary and successful completion."""

import hashlib
import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import traffic_tool
from traffic_dispatch import verify_tool_actions
from traffic_runtime import scenario_action_verification
from traffic_tool import (
    attributed_arguments,
    native_binary,
    nikto_configuration,
    worker_arguments,
)


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


def test_nikto_child_config_preserves_native_paths_and_test_identity(tmp_path):
    source = tmp_path / "native.conf"
    source.write_text(
        "USERAGENT=Mozilla/5.00 (Nikto/@VERSION) (Test:@TESTID)\nPLUGINDIR=/native/plugins\nUPDATES=yes\n"
    )
    output = nikto_configuration(source, tmp_path, "child-opaque")
    text = output.read_text()
    assert "PLUGINDIR=/native/plugins" in text
    assert "Nikto/@VERSION" in text
    assert "Test:@TESTID" in text
    assert "TGen-Child/child-opaque" in text
    assert "UPDATES=no" in text
    assert output.stat().st_mode & 0o077 == 0


def test_timed_native_workers_keep_original_arguments_and_add_opaque_attribution():
    args = ["-c", "2", "https://example.com/httpbin/get"]
    for tool in ("wrk", "hey", "ab"):
        result = worker_arguments(tool, args, tool + "-123")
        assert result[: len(args) - 1] == args[:-1]
        assert ["-H", "X-TGen-Worker: " + tool + "-123"] == result[
            len(args) - 1 : len(args) + 1
        ]
        if tool == "ab":
            assert result[-3:-1] == ["-H", "User-Agent: tgen-native-load/1.0"]
        assert result[-1] == args[-1]
    assert worker_arguments("vegeta", args, "vegeta-123") == args


def test_native_apachebench_accepts_worker_header_before_final_target():
    binary = shutil.which("ab")
    if binary is None:
        pytest.skip("native ApacheBench unavailable")
    assert binary is not None

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # pylint: disable=invalid-name
            body = b"synthetic"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        args = worker_arguments(
            "ab",
            ["-n", "2", "-c", "1", f"http://127.0.0.1:{server.server_port}/"],
            "ab-123",
        )
        result = subprocess.run(  # noqa: S603 - native tool against owned loopback fixture
            [binary, *args], capture_output=True, text=True, timeout=10, check=False
        )
        assert result.returncode == 0, result.stderr
        assert "Complete requests:      2" in result.stdout
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_apachebench_preserves_explicit_user_agent():
    args = ["-H", "User-Agent: declared-synthetic", "https://example.test/httpbin/get"]
    result = worker_arguments("ab", args, "ab-123")
    assert result.count("User-Agent: declared-synthetic") == 1
    assert "User-Agent: tgen-native-load/1.0" not in result


def test_native_load_worker_keeps_child_marker_and_final_target():
    arguments = [
        "-t2",
        "-c20",
        "-d15s",
        "https://www.example.test/juice-shop/rest/products/search?q=test",
    ]
    for tool in ("wrk", "hey", "ab"):
        result = attributed_arguments(tool, arguments, "child-opaque")
        assert result[:-3] == arguments[:-1]
        assert result[-3:-1] == ["-H", "X-TGen-Child: child-opaque"]
        assert result[-1] == arguments[-1]


@pytest.mark.parametrize("matches", [True, False])
def test_native_tool_contract_is_matched_before_attribution_headers(
    tmp_path, monkeypatch, matches
):
    binary = tmp_path / "native-wrk"
    binary.write_bytes(b"synthetic immutable native tool")
    target = "https://example.test/juice-shop/rest/products/search?q=test"
    arguments = ["-t2", "-c20", "-d15s", target]
    requirement = {
        "id": "native-load",
        "tool": "wrk",
        "argument_regex": (
            r"^-t2 -c20 -d15s https://example\.test/juice-shop/rest/products/search\?q=test$"
            if matches
            else r"^-t2 -c20 -d30s "
        ),
    }
    monkeypatch.setattr(
        sys, "argv", ["traffic_tool.py", str(binary), "wrk", *arguments]
    )
    monkeypatch.setenv(
        "TGEN_TOOL_CONTRACT", json.dumps({"requirements": [requirement]})
    )
    monkeypatch.setenv("TGEN_CHILD_MARKER", "child-opaque")
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    calls = []

    def execute(argv, *, check):
        assert check is False
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(traffic_tool.subprocess, "run", execute)
    assert traffic_tool.main() == 0
    events_path = tmp_path / "tool-events.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    assert len(events) == 2
    assert events[0]["completed"] is False
    assert events[1]["completed"] is True
    assert events[1]["exit_code"] == 0
    assert events[1]["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert events[1]["matched_requirements"] == (["native-load"] if matches else [])
    assert events_path.stat().st_mode & 0o077 == 0
    assert calls == [
        [
            str(binary),
            *arguments[:-1],
            "-H",
            "X-TGen-Child: child-opaque",
            "-H",
            "X-TGen-Worker: " + events[1]["worker_marker"],
            target,
        ]
    ]
