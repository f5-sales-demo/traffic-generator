"""Declared Nuclei technology coverage must execute before filtering severity."""

import json
import os
import subprocess
from pathlib import Path


def test_technology_phase_precedes_existing_medium_high_critical_scan(tmp_path):
    log = tmp_path / "argv.jsonl"
    executable = tmp_path / "nuclei"
    executable.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['CALL_LOG'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\n"
    )
    executable.chmod(0o700)
    root = Path(__file__).parents[1]
    subprocess.run(  # noqa: S603 - fixed local script with synthetic target and stub scanner
        [
            "/usr/bin/bash",
            str(root / "suites/web-app-attacks/06-nuclei-scan.sh"),
            "www.example.test",
        ],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "CALL_LOG": str(log),
            "TARGET_PROTOCOL": "https",
        },
        check=True,
        capture_output=True,
    )
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(rows) == 2
    assert "/opt/nuclei-templates/http/technologies/tech-detect.yaml" in rows[0]
    assert "-severity" not in rows[0]
    assert rows[1][rows[1].index("-severity") + 1] == "medium,high,critical"
