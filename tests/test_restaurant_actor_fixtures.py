"""BOLA actors must refer to distinct real synthetic account identities."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fixture_token import restaurant_actors


def test_bola_actors_reject_shared_identity_or_missing_token():
    fixtures = {
        "restaurant_attacker": {
            "username": "tgen_bola_attacker",
            "token": "issued-attacker",
        },
        "restaurant_victim": {"username": "tgen_bola_victim", "token": "issued-victim"},
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
