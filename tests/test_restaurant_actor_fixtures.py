"""BOLA actors must refer to distinct real synthetic account identities."""

import base64
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import traffic_runtime as runtime
from fixture_token import restaurant_actors
from traffic_functional import verify_profile_restoration


def issued(username: str, expires: float) -> str:
    payload = (
        base64.urlsafe_b64encode(json.dumps({"sub": username, "exp": expires}).encode())
        .decode()
        .rstrip("=")
    )
    return "synthetic." + payload + ".signature"


def test_bola_actors_reject_shared_identity_or_missing_token():
    fixtures = {
        "restaurant_attacker": {
            "username": "tgen_bola_attacker",
            "token": issued("tgen_bola_attacker", time.time() + 60),
        },
        "restaurant_victim": {
            "username": "tgen_bola_victim",
            "token": issued("tgen_bola_victim", time.time() + 60),
        },
    }
    assert (
        restaurant_actors(fixtures)[0]["username"]
        != restaurant_actors(fixtures)[1]["username"]
    )
    fixtures["restaurant_victim"]["token"] = fixtures["restaurant_attacker"]["token"]
    with pytest.raises(ValueError, match="distinct"):
        restaurant_actors(fixtures)
    fixtures["restaurant_victim"]["token"] = ""
    with pytest.raises(ValueError, match="fixture absent"):
        restaurant_actors(fixtures)


def test_bola_actor_rejects_expired_or_wrong_subject_token():
    fixtures = {
        "restaurant_attacker": {
            "username": "tgen_bola_attacker",
            "token": issued("tgen_bola_attacker", time.time() + 60),
        },
        "restaurant_victim": {
            "username": "tgen_bola_victim",
            "token": issued("tgen_bola_victim", time.time() - 1),
        },
    }
    with pytest.raises(ValueError, match="expired"):
        restaurant_actors(fixtures)
    fixtures["restaurant_victim"]["token"] = issued("other-actor", time.time() + 60)
    with pytest.raises(ValueError, match="identity"):
        restaurant_actors(fixtures)


def test_missing_profile_restoration_fails_scenario(tmp_path):
    scenario = {"budget": "http", "fixture_contract": {"restore_profiles": True}}
    result = {"outcome": "launched", "dispatch_contract_verified": True}
    runtime.scenario_action_verification(tmp_path, scenario, result)
    assert not result["dispatch_contract_verified"]
    assert result["outcome"] == "fixture_failure"
    (tmp_path / "fixture-restoration.json").write_text('{"restored":true}')
    result = {"outcome": "launched", "dispatch_contract_verified": True}
    runtime.scenario_action_verification(tmp_path, scenario, result)
    assert result["dispatch_contract_verified"]


def test_profile_restore_contract_requires_every_named_native_readback(tmp_path):
    scenario = {"functional_contract": {"profile_actors": ["victim", "admin"]}}
    before = [
        {
            "actor": "victim",
            "username": "tgen_bola_victim",
            "phone_number": "8005550100",
        },
        {"actor": "admin", "username": "tgen_bola_admin", "phone_number": "8005550101"},
    ]
    (tmp_path / "restaurant-profile-snapshot.jsonl").write_text(
        "\n".join(json.dumps(r) for r in before)
    )
    receipt: dict = {
        "restored": True,
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "actors": [{"before": r, "after": r} for r in before],
    }
    p = tmp_path / "fixture-restoration.json"
    p.write_text(json.dumps(receipt))
    result = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    assert verify_profile_restoration(scenario, result, tmp_path)
    receipt["actors"].pop()
    p.write_text(json.dumps(receipt))
    assert not verify_profile_restoration(scenario, result, tmp_path)
