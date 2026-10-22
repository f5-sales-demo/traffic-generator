"""Sequence journaled native load and every declared child suite under shared pacing."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from traffic_family_native import main as family_run


def main() -> int:
    """Complete native load restoration before children acquire individual journals."""
    root = Path(__file__).resolve().parents[1]
    scenario = next(
        r
        for r in json.loads((root / "suites/catalog.json").read_text())["scenarios"]
        if r["id"] == sys.argv[1]
    )
    os.environ["TGEN_LOAD_JOURNAL_ONLY"] = "1"
    code = family_run()
    os.environ.pop("TGEN_LOAD_JOURNAL_ONLY")
    if code:
        return code
    failed = False
    for suite in scenario["nested_contract"]:
        environment = {
            **os.environ,
            "TGEN_RESULTS_DIR": str(
                Path(os.environ["TGEN_RESULTS_DIR"]) / ("nested-" + suite)
            ),
        }
        result = subprocess.run(  # noqa: S603 - validated native suite entrypoints
            ["/usr/bin/bash", str(root / "suites/runner.sh"), suite],
            env=environment,
            check=False,
        )
        failed |= result.returncode != 0
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
