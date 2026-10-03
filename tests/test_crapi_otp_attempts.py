"""Exercise native shell OTP batches with deterministic application responses."""

import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_otp_receipt_counts_both_batches_and_preserves_rejections(tmp_path):
    curl = tmp_path / "curl"
    curl.write_text("""#!/usr/bin/env python3
import json, pathlib, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://'))
body = args[args.index('-d') + 1] if '-d' in args else ''
if '/mailhog/' in url:
    print(json.dumps({'items': [{'Raw': {'To': ['otp@example.com'], 'Data': 'OTP 1234'}}]}))
elif 'login' in url:
    print(json.dumps({'token': 'synthetic.jwt.token'}))
elif 'check-otp' in url and '-o' in args:
    pathlib.Path(args[args.index('-o') + 1]).write_text(json.dumps({'message': 'Invalid OTP! Please try again..', 'status': 500}))
    print('500')
elif 'check-otp' in url:
    print('{}\\n200')
elif '-w' in args:
    print('{}\\n200')
else:
    print('{}')
""")
    curl.chmod(0o700)
    sleep = tmp_path / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o700)
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "suites/crapi-exploits/04-otp-bruteforce.sh"),
            "www.example.test",
        ],
        env=dict(
            os.environ,
            PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
            TARGET_PROTOCOL="https",
            TGEN_CONCURRENCY="4",
        ),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Total attempts: 14" in result.stdout, result.stdout
    assert "Application rejections (500): 14" in result.stdout, result.stdout
    assert "Full 0000-9999 keyspace is feasible" not in result.stdout
