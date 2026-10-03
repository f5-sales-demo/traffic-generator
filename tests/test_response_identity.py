"""Positive API identity checks must reject the wrong document even at HTTP 200."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_dispatch import response_content_matches, verify_responses


def test_positive_response_requires_declared_identity_and_content_type():
    contract = {
        "requirements": [
            {
                "id": "profile",
                "minimum_dispatches": 1,
                "expected_statuses": [200],
                "response_contract": {
                    "content_type": "application/json",
                    "json_equals": {"username": "tgen_bola_victim"},
                },
            }
        ]
    }
    event: dict = {
        "kind": "scenario",
        "status": 200,
        "matched_requirements": ["profile"],
        "response_assertions": {"profile": False},
    }
    assert not verify_responses(contract, [event])["passed"]
    event["response_assertions"]["profile"] = True
    assert verify_responses(contract, [event])["passed"]


def test_transient_response_matcher_rejects_landing_and_wrong_actor():
    contract = {
        "content_type": "application/json",
        "json_equals": {"username": "tgen_bola_victim"},
    }
    assert not response_content_matches(contract, "text/html", "Origin Server")
    assert not response_content_matches(
        contract, "application/json", '{"username":"tgen_bola_attacker"}'
    )
    assert response_content_matches(
        contract, "application/json; charset=utf-8", '{"username":"tgen_bola_victim"}'
    )


def test_seeded_response_requires_nonempty_object_list():
    contract = {
        "content_type": "application/json",
        "json_nonempty_lists": {"posts": ["id", "title", "content"]},
    }
    assert not response_content_matches(contract, "application/json", '{"posts":[]}')
    assert not response_content_matches(contract, "application/json", '{"posts":[{}]}')
    assert response_content_matches(
        contract,
        "application/json",
        '{"posts":[{"id":"fixture","title":"Synthetic","content":"Fixture"}]}',
    )
