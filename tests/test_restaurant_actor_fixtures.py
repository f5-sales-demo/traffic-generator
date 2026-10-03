"""BOLA actors must refer to distinct real synthetic account identities."""

import base64
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fixture_token import restaurant_actors


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
