"""Orphan targets and incomplete application inventory fail readiness contracts."""

import copy
import sys
import unittest
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_catalog import load_catalog, validate_catalog  # noqa: E402


class ApplicationCoverageTests(unittest.TestCase):
    """Verify application ownership for every catalog target."""

    def test_orphan_target_fails_validation(self):
        """A synthetic undeclared endpoint cannot establish hosted coverage."""
        catalog = copy.deepcopy(load_catalog(ROOT))
        catalog["scenarios"][0]["target_paths"] = ["/WAF/SQL"]
        with pytest.raises(ValueError, match="no declared application"):
            validate_catalog(ROOT, catalog)


if __name__ == "__main__":
    unittest.main()
