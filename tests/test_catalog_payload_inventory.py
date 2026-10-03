"""Reconciled action contracts retain the actual payload inventory."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_catalog import validate_catalog  # noqa: E402


def test_expanded_scenario_contracts_preserve_distinct_actions():
    catalog = json.loads((ROOT / "suites/catalog.json").read_text())
    by_id = {scenario["id"]: scenario for scenario in catalog["scenarios"]}
    expected = {
        "api-attacks/01-vampi-owasp-top10": 22,
        "juice-shop-exploits/01-sqli-login-bypass": 5,
        "juice-shop-exploits/02-sqli-search-union": 19,
        "juice-shop-exploits/08-nosql-injection": 21,
        "traffic-generation/03-http-methods": 190,
    }
    for identifier, count in expected.items():
        requirements = by_id[identifier]["dispatch_contract"]["requirements"]
        assert len(requirements) == count
        assert len({requirement["id"] for requirement in requirements}) == count
    queries = by_id["juice-shop-exploits/02-sqli-search-union"]["dispatch_contract"][
        "requirements"
    ]
    assert all("query_values" in requirement for requirement in queries)
    assert len(catalog["scenarios"]) == 164
    assert len(catalog["suites"]) == 22


def test_missing_scenario_execution_contract_fails_validation():
    catalog = json.loads((ROOT / "suites/catalog.json").read_text())
    scenario = catalog["scenarios"][0]
    scenario.pop("dispatch_contract", None)
    with pytest.raises(ValueError, match="execution contract"):
        validate_catalog(ROOT, catalog)
