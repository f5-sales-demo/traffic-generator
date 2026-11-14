"""False native load success must fail even with positive dispatch counts."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from stress_reports import report_matches, verify_native_reports
from traffic_runtime import scenario_action_verification


def test_native_errors_and_empty_reports_fail():
    assert not report_matches("wrk", "Usage: wrk")
    assert not report_matches(
        "wrk", "10 requests in 10s\nRequests/sec: 1\nSocket errors: connect 0, read 1"
    )
    assert report_matches("wrk", "10 requests in 10s\nRequests/sec: 1")
    assert not report_matches(
        "hey",
        "Requests/sec: 1\nStatus code distribution:\n[200] 10 responses\nError distribution: EOF",
    )
    assert report_matches(
        "hey", "Requests/sec: 1\nStatus code distribution:\n[200] 10 responses"
    )
    assert not report_matches(
        "ab", "Complete requests: 10\nFailed requests: 1\nRequests per second: 1"
    )
    assert report_matches(
        "ab", "Complete requests: 10\nFailed requests: 0\nRequests per second: 1"
    )
    assert not report_matches("vegeta", '{"code":0,"error":"timeout"}')
    assert report_matches(
        "vegeta", '{"code":200,"error":""}\n{"code":403,"error":"403 Forbidden"}'
    )
    assert not report_matches("vegeta", "")


def test_missing_worker_cannot_pass_from_other_worker_report(tmp_path):
    (tmp_path / "wrk-one.log").write_text("10 requests in 10s\nRequests/sec: 1")
    assert not verify_native_reports(tmp_path, {"wrk": 2})["passed"]
    assert verify_native_reports(tmp_path, {"wrk": 1})["passed"]


def test_native_report_gate_cannot_be_overwritten_by_dispatch_success(tmp_path):
    requirement = {
        "id": "load",
        "method": "GET",
        "path": "/httpbin/get",
        "payload_class": "load",
        "minimum_dispatches": 1,
    }
    (tmp_path / "dispatch-events.jsonl").write_text(
        json.dumps({"kind": "scenario", "matched_requirements": ["load"]}) + "\n"
    )
    scenario = {
        "id": "native-load",
        "budget": "http",
        "dispatch_contract": {"requirements": [requirement]},
        "native_report_contract": {"wrk": 1},
    }
    result = {"outcome": "launched", "dispatch_contract_verified": False}
    scenario_action_verification(tmp_path, scenario, result)
    assert not result["dispatch_contract_verified"]
    assert result["outcome"] == "tool_failure"


SQLMAP_COMPLETE = """{1.9.7#stable}
[*] starting @ 12:00:00 /2026-01-01/
[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [WARNING] all tested parameters do not appear to be injectable
[*] ending @ 12:00:03 /2026-01-01/
"""


def test_sqlmap_native_report_requires_scan_and_terminal_result():
    assert report_matches("sqlmap", SQLMAP_COMPLETE)
    for text in (
        "",
        SQLMAP_COMPLETE.split("[*] ending", maxsplit=1)[0],
        SQLMAP_COMPLETE.replace(
            "[12:00:01] [INFO] testing connection to the target URL\n", ""
        ),
        SQLMAP_COMPLETE.replace(
            "all tested parameters do not appear to be injectable", "scan pending"
        ),
        SQLMAP_COMPLETE + "[CRITICAL] unable to connect to the target URL",
        SQLMAP_COMPLETE + "[WARNING] connection timed out to the target URL",
    ):
        assert not report_matches("sqlmap", text)


def test_sqlmap_requires_exact_five_completed_target_reports(tmp_path):
    targets = ("search", "login", "track", "feedback", "register")
    for target in targets[:-1]:
        (tmp_path / f"sqlmap-{target}.log").write_text(SQLMAP_COMPLETE)
    (tmp_path / "sqlmap-unrelated.log").write_text(SQLMAP_COMPLETE)
    assert not verify_native_reports(tmp_path, {"sqlmap": 5})["passed"]
    (tmp_path / "sqlmap-register.log").write_text(SQLMAP_COMPLETE)
    assert verify_native_reports(tmp_path, {"sqlmap": 5})["passed"]
    (tmp_path / "sqlmap-login.log").write_text("[*] starting @ 12:00:00")
    assert not verify_native_reports(tmp_path, {"sqlmap": 5})["passed"]
