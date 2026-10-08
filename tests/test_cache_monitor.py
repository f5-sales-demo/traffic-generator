"""Cache monitors distinguish transport failures from a successful dynamic response."""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cache_monitor_requires_successful_http_request(tmp_path):
    wrapper = tmp_path / "curl"
    wrapper.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$MONITOR_ARGS"\n[ "$MONITOR_EXIT" = 0 ] || exit "$MONITOR_EXIT"\nprintf \'%s\\n\' "$MONITOR_HEADERS"\n'
    )
    wrapper.chmod(0o755)
    args = tmp_path / "args.txt"
    for exit_code, headers, expected in [
        (0, "HTTP/1.1 200 OK", "NONE"),
        (0, "HTTP/1.1 200 OK\nX-Cache-Status: BYPASS", "BYPASS"),
        (22, "HTTP/1.1 503 Unavailable", None),
        (28, "", None),
    ]:
        environment = dict(
            os.environ,
            PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
            TARGET_FQDN="www.example.test",
            MONITOR_EXIT=str(exit_code),
            MONITOR_HEADERS=headers,
            MONITOR_ARGS=str(args),
        )
        command = '. "$1"; check_cache_status "https://www.example.test/httpbin/get"'
        result = subprocess.run(  # noqa: S603 - fixed local test with mock curl
            [
                "/bin/bash",
                "-c",
                command,
                "monitor",
                str(ROOT / "suites/cdn-load-testing/_lib.sh"),
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if expected is None:
            assert result.returncode != 0
            assert result.stdout == ""
        else:
            assert result.returncode == 0
            assert result.stdout.strip() == expected
        assert "X-TGen-Monitor: cache-status" in args.read_text()
