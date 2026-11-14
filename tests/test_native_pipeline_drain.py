"""Display limits must drain every native scanner result without SIGPIPE."""

import re
import subprocess
import sys
from pathlib import Path


def test_mitre_native_tool_output_is_fully_drained():
    root = Path(__file__).parents[1]
    for name in (
        "01-reconnaissance.sh",
        "02-initial-access.sh",
        "04-credential-access.sh",
    ):
        source = (root / "suites/mitre-attack" / name).read_text()
        assert "| head -" not in source
        assert "sed -n" in source


def test_ffuf_display_limit_preserves_complete_native_workload():
    source = (
        Path(__file__).parents[1] / "suites/mitre-attack/01-reconnaissance.sh"
    ).read_text()
    match = re.search(r"ffuf .*?\| (.+)", source, re.DOTALL)
    assert match is not None
    display = match.group(1).splitlines()[0]
    result = subprocess.run(  # noqa: S603 - source-owned display filter and synthetic native output
        [
            "/bin/bash",
            "-o",
            "pipefail",
            "-c",
            '"$1" -c "$2" | ' + display,
            "drain-regression",
            sys.executable,
            "for number in range(100000): print(number)",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [str(number) for number in range(20)]
