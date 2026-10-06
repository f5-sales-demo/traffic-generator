"""Native curl requests with retained bytes for content verification."""

import os
import subprocess
import tempfile
from pathlib import Path


def request(url: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
    """Execute native curl inside the inherited pacing namespace; preserve real responses."""
    root = Path(os.environ.get("TGEN_RESULTS_DIR", tempfile.gettempdir()))
    with tempfile.TemporaryDirectory(dir=root) as temporary:
        directory = Path(temporary)
        body, response_headers = directory / "body", directory / "headers"
        argv = [
            "/usr/bin/curl",
            "--silent",
            "--show-error",
            "--max-time",
            "60",
            "--output",
            str(body),
            "--dump-header",
            str(response_headers),
            "--write-out",
            "%{http_code}",
        ]
        for name, value in (headers or {}).items():
            argv.extend(["-H", name + ": " + value])
        process = subprocess.run([*argv, url], capture_output=True, check=False)  # noqa: S603 - native curl exact argument array
        if process.returncode:
            message = "native curl transport failure"
            raise OSError(message)
        parsed = {}
        for line in response_headers.read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                parsed[key.lower()] = value.strip()
        return int(process.stdout), parsed, body.read_bytes()
