"""The retired substitute cannot produce benchmark acceptance."""

import subprocess
import sys
from pathlib import Path


def test_retired_python_benchmark_fails_without_launching_requests():
    process = subprocess.run(  # noqa: S603 - exact local retired script
        [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "scripts/traffic_benchmark.py"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode != 0
    assert "substitution retired" in process.stderr
