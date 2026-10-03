"""Malformed scanner API status cannot be parsed as completed work."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script", ["01-zap-baseline.sh", "02-zap-active-scan.sh"])
def test_zap_status_parser_rejects_missing_and_malformed_completion(script):
    source = (ROOT / "suites/owasp-scanning" / script).read_text()
    parsers = re.findall(r'python3 -c "([^"]*json.load[^\"]*)"', source)
    status = next(parser for parser in parsers if "['status']" in parser)
    for payload in ["{}", "not-json", '{"status":"unfinished"}']:
        result = subprocess.run(  # noqa: S603 - source-owned parser with synthetic input
            [sys.executable, "-c", status],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
        )
        if payload == '{"status":"unfinished"}':
            assert not result.stdout.strip().isdigit()
        else:
            assert result.returncode != 0
    assert "did not complete within the timeout" not in source or "exit 1" in source
