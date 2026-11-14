"""Ordered catalog and read-only readiness contracts."""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class CatalogTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "traffic_catalog", ROOT / "scripts/traffic_catalog.py"
        )
        assert spec is not None
        assert spec.loader is not None
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_complete(self):
        catalog = self.module.load_catalog(ROOT)
        numbered = {
            str(p.relative_to(ROOT))
            for p in (ROOT / "suites").glob("*/[0-9]*")
            if p.is_file()
        }
        recorded = {
            s["entrypoint"] for s in catalog["scenarios"] if s["kind"] != "csd-browser"
        }
        assert numbered <= recorded
        assert len(numbered) == 151
        assert sum(s["kind"] == "csd-browser" for s in catalog["scenarios"]) == 11
        assert len(catalog["suites"]) == 22

    def test_missing_scenario_fails(self):
        catalog = self.module.load_catalog(ROOT)
        catalog["scenarios"].pop(0)
        with pytest.raises(ValueError, match="missing ordered dependency"):
            self.module.validate_catalog(ROOT, catalog)

    def test_missing_suite_is_rejected(self):
        catalog = self.module.load_catalog(ROOT)
        catalog["suites"].pop()
        with pytest.raises(ValueError, match="suite inventory"):
            self.module.validate_catalog(ROOT, catalog)

    def test_missing_tool_is_failure(self):
        result = self.module.readiness(
            ROOT, self.module.load_catalog(ROOT), find_tool=lambda _: None
        )
        assert not result["ready"]
        assert result["missing_tools"]

    def test_missing_asset_is_readiness_failure(self):
        catalog = self.module.load_catalog(ROOT)
        catalog["required_assets"] = ["/absent-catalog-synthetic-fixture"]
        result = self.module.readiness(ROOT, catalog, find_tool=lambda _: "/bin/true")
        assert not result["ready"]
        assert result["missing_assets"]

    def test_dry_run_has_no_writes_or_config_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "PATH": os.environ["PATH"],
                "CONFIG_FILE": tmp + "/missing",
                "RESULTS_DIR": tmp + "/results",
            }
            result = subprocess.run(  # noqa: S603 - fixed regression command
                [
                    "/bin/bash",
                    str(ROOT / "suites/runner.sh"),
                    "bot-simulation",
                    "--dry-run",
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, result.stderr
            assert len(json.loads(result.stdout)["scenarios"]) == 5
            assert not list(pathlib.Path(tmp).iterdir())

    def test_csd_dry_run_includes_all_simulations(self):
        result = subprocess.run(  # noqa: S603 - fixed regression command
            [
                "/bin/bash",
                str(ROOT / "suites/runner.sh"),
                "csd-violations",
                "--dry-run",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert len(json.loads(result.stdout)["scenarios"]) == 11


if __name__ == "__main__":
    unittest.main()
