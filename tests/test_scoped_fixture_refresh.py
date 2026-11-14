"""Unrelated login setup cannot eliminate intentional unauthenticated launches."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from traffic_catalog import validate_fixture_refresh
from traffic_network import NetworkBoundary

ROOT = Path(__file__).resolve().parents[1]


def test_no_fixture_contract_performs_no_login(tmp_path):
    runtime = tmp_path / "results"
    runtime.mkdir()
    boundary = NetworkBoundary(
        ROOT, {"domains": ["www.example.test", "api.example.test"]}, runtime
    )
    with patch.object(
        boundary, "fixture_login", side_effect=AssertionError("unrelated login")
    ):
        boundary.refresh_fixtures("www.example.test", [])
    boundary.state.pool.shutdown()


def test_vampi_fixture_contract_only_authenticates_vampi(tmp_path):
    runtime = tmp_path / "results"
    runtime.mkdir()
    boundary = NetworkBoundary(
        ROOT, {"domains": ["www.example.test", "api.example.test"]}, runtime
    )
    with patch.object(
        boundary, "fixture_login", return_value={"auth_token": "synthetic"}
    ) as login:
        boundary.refresh_fixtures("www.example.test", ["vampi"])
    assert login.call_count == 1
    assert login.call_args.args[1] == "/vampi/users/v1/login"
    boundary.state.pool.shutdown()


def test_shadow_endpoints_declare_no_authentication_fixture():
    catalog = json.loads((ROOT / "suites/catalog.json").read_text())
    scenario = next(
        item
        for item in catalog["scenarios"]
        if item["id"] == "api-protection-verify/02-shadow-endpoints"
    )
    assert scenario["fixture_refresh"] == []
    assert all(
        set(item["fixture_refresh"]) <= {"vampi", "crapi", "juice", "restaurant"}
        for item in catalog["scenarios"]
    )


@pytest.mark.parametrize(
    "families", [None, "crapi", ["unknown"], ["crapi", "crapi"], [1]]
)
def test_invalid_fixture_refresh_contract_fails(families):
    with pytest.raises(ValueError, match="fixture refresh contract"):
        validate_fixture_refresh({"fixture_refresh": families})
