"""An unprovisioned OTP attack cannot pass by fabricating native responses."""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_otp_requires_isolated_managed_fixture():
    environment = dict(os.environ)
    environment.pop("TGEN_FIXTURES", None)
    environment["TARGET_PROTOCOL"] = "https"
    # No external request: the required fixture check must precede reachability.
    result = subprocess.run(  # noqa: S603 - checked-in shell and owned argument
        [
            "/bin/bash",
            str(ROOT / "suites/crapi-exploits/04-otp-bruteforce.sh"),
            "www.example.test",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "Isolated managed OTP fixture required" in result.stdout
