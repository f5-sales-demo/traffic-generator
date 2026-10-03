"""Orphan targets and incomplete application inventory fail readiness contracts."""

import copy
import sys
import unittest
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_catalog import (  # noqa: E402  # pylint: disable=wrong-import-position
    load_catalog,
    validate_catalog,
)


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


def test_server_errors_require_case_specific_reconciliation():
    """Generated payload-class status lists cannot accept arbitrary application crashes."""
    catalog = load_catalog(ROOT)
    assert not any(
        500 in requirement.get("expected_statuses", [])
        for scenario in catalog["scenarios"]
        for requirement in scenario.get("dispatch_contract", {}).get("requirements", [])
    )


def test_community_exposure_reads_seeded_posts_without_duplicate_creation():
    source = (ROOT / "suites/crapi-exploits/06-data-exposure-posts.sh").read_text()
    assert "Test Post ${RANDOM}" not in source
    assert "Seeded community post prerequisite is missing" in source
    assert "/community/api/v2/community/posts/recent?limit=20&offset=0" in source


def test_target_matrix_cannot_omit_exact_execution_endpoint():
    catalog = copy.deepcopy(load_catalog(ROOT))
    scenario = next(
        s
        for s in catalog["scenarios"]
        if s["id"] == "crapi-exploits/06-data-exposure-posts"
    )
    scenario["target_paths"] = ["/crapi/"]
    with pytest.raises(ValueError, match="execution endpoint missing"):
        validate_catalog(ROOT, catalog)
