"""Read-only status and readiness-gated control contracts."""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ControlTests(unittest.TestCase):
    def test_status_reads_structured_config_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            runtime = root / "private-runtime"
            runtime.mkdir()
            (runtime / "status.json").write_text(
                json.dumps({"status": "running", "current_scenario": "synthetic"})
            )
            config = root / "config.json"
            config.write_text(json.dumps({"results_dir": str(runtime)}))
            result = subprocess.run(  # noqa: S603 - fixed control regression command
                ["/bin/bash", str(ROOT / "scripts/tgen-control"), "status"],
                env=dict(os.environ, TGEN_ROOT=tmp, CATALOG_CONFIG=str(config)),
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0
            assert json.loads(result.stdout)["current_scenario"] == "synthetic"


if __name__ == "__main__":
    unittest.main()
