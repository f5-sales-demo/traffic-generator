"""Verify retained native load reports independently of dispatched request counts."""

import hashlib
import json
import re
from http import HTTPStatus
from pathlib import Path


def report_matches(tool: str, text: str) -> bool:
    """Require a completed nonempty native report and no transport-error evidence."""
    if tool == "vegeta":
        try:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError:
            return False
        return bool(rows) and all(
            isinstance(row, dict)
            and isinstance(row.get("code"), int)
            and row["code"] in {status.value for status in HTTPStatus}
            and row.get("error", "")
            in ("", str(row["code"]), f"{row['code']} {HTTPStatus(row['code']).phrase}")
            for row in rows
        )
    if tool == "wrk":
        completed = re.search(r"\b([1-9][0-9]*) requests in", text)
        return (
            bool(completed)
            and "Requests/sec:" in text
            and not any(
                term in text
                for term in ("Socket errors:", "unable to connect", "Usage:")
            )
        )
    if tool == "hey":
        total = re.search(r"\[([2-5][0-9]{2})\]\s+([1-9][0-9]*) responses", text)
        return (
            bool(total)
            and "Requests/sec:" in text
            and "Error distribution:" not in text
        )
    if tool == "ab":
        completed = re.search(r"Complete requests:\s+([1-9][0-9]*)", text)
        errors = re.search(r"Failed requests:\s+([0-9]+)", text)
        return (
            bool(completed and errors and errors[1] == "0")
            and "Requests per second:" in text
            and "SSL read failed" not in text
        )
    return False


def verify_native_reports(directory: Path, contract: dict) -> dict:
    """Bind each required worker report to its retained bytes and parser outcome."""
    checks = []
    for tool, minimum in contract.items():
        pattern = "vegeta-*.bin" if tool == "vegeta" else tool + "-*.log"
        files = sorted(directory.glob(pattern))
        rows = [
            {
                "file": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "passed": report_matches(tool, path.read_text()),
            }
            for path in files
            if path.is_file() and not path.is_symlink()
        ]
        checks.append(
            {
                "tool": tool,
                "minimum": minimum,
                "reports": rows,
                "passed": len(rows) >= minimum and all(row["passed"] for row in rows),
            }
        )
    return {
        "passed": bool(checks) and all(check["passed"] for check in checks),
        "checks": checks,
    }
