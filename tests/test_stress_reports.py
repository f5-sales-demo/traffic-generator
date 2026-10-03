"""False native load success must fail even with positive dispatch counts."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from stress_reports import report_matches, verify_native_reports


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
