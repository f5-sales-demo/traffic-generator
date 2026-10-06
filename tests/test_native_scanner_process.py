"""Actual subprocess cleanup regression checks; no simulated process results."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from native_scanner_process import run_scanner


def test_native_process_completion(tmp_path):
    receipt = run_scanner(
        [sys.executable, "-c", "import time; time.sleep(0.2)"],
        dict(os.environ),
        tmp_path / "completed.log",
        5,
    )
    assert receipt["exit_code"] == 0
    assert receipt["observed_process_count"] >= 1
    assert receipt["connections_closed"] is True
    assert receipt["timed_out"] is False


def test_native_process_timeout_fails_and_cleans(tmp_path):
    receipt = run_scanner(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        dict(os.environ),
        tmp_path / "timeout.log",
        1,
    )
    assert receipt["exit_code"] != 0
    assert receipt["timed_out"] is True
    assert receipt["remaining_after_cleanup"] == []


def test_native_descendant_cannot_qualify_cleanup(tmp_path):
    receipt = run_scanner(
        [
            sys.executable,
            "-c",
            "import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(0.2)",
        ],
        dict(os.environ),
        tmp_path / "descendant.log",
        5,
    )
    assert receipt["remaining_before_cleanup"]
    assert receipt["connections_closed"] is False
    assert receipt["remaining_after_cleanup"] == []
