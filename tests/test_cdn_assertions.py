"""CDN assertion failures remain process failures, never informational success."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cdn_summary_propagates_failed_assertion():
    library = ROOT / "suites/cdn-load-testing/_lib.sh"
    result = subprocess.run(  # noqa: S603 - fixed regression script and checked-in library

        [
            shutil.which("bash") or "/bin/bash",
            "-c",
            'source "$1"; fail "synthetic failure"; summary',
            "bash",
            str(library),
            "www.example.test",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
