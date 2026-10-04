"""Positive API identity checks must reject the wrong document even at HTTP 200."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_dispatch import (
    classify_outcome,
    response_content_matches,
    verify_responses,
)


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


def test_expected_application_500_requires_exact_status_content_assertion():
    contract = {
        "requirements": [
            {
                "id": "invalid-otp",
                "expected_statuses": [200, 500],
                "minimum_dispatches": 1,
                "response_contract_by_status": {
                    "500": {
                        "content_type": "application/json",
                        "json_equals": {
                            "message": "Invalid OTP! Please try again..",
                            "status": 500,
                        },
                    }
                },
            }
        ]
    }
    event = {"kind": "scenario", "status": 500, "matched_requirements": ["invalid-otp"]}
    assert not verify_responses(contract, [event])["passed"]
    assert verify_responses(
        contract, [{**event, "response_assertions": {"invalid-otp": True}}]
    )["passed"]


def test_missing_coupon_contract_rejects_database_errors_and_blocked_control():
    content = {"content_type": "application/json", "json_document_equals": {}}
    assert response_content_matches(content, "application/json", "{}")
    assert not response_content_matches(
        content, "application/json", '{"error":"database unavailable"}'
    )
    requirement = {
        "id": "control",
        "minimum_dispatches": 1,
        "expected_statuses": [500],
        "require_application_response": True,
        "response_contract_by_status": {"500": content},
    }
    event = {
        "kind": "scenario",
        "status": 500,
        "matched_requirements": ["control"],
        "response_assertions": {"control": True},
    }
    assert verify_responses({"requirements": [requirement]}, [event])["passed"]
    assert not verify_responses(
        {"requirements": [requirement]}, [{**event, "status": 403}]
    )["passed"]
    assert not verify_responses(
        {"requirements": [requirement]},
        [{**event, "response_assertions": {"control": False}}],
    )["passed"]


def test_expensive_graphql_batch_requires_each_nonempty_data_result():
    spec = {
        "content_type": "application/json",
        "graphql_data_field": "systemUpdate",
        "graphql_response_count": 2,
    }
    assert response_content_matches(
        spec,
        "application/json",
        '[{"data":{"systemUpdate":"done"}},{"data":{"systemUpdate":"done"}}]',
    )
    assert not response_content_matches(
        spec, "application/json", '[{"data":{"systemUpdate":"done"}}]'
    )
    assert not response_content_matches(
        spec,
        "application/json",
        '[{"data":{"systemUpdate":"done"}},{"data":{"systemUpdate":null},"errors":[{"message":"failed"}]}]',
    )
    assert not response_content_matches(
        spec, "application/json", '{"message":"systemUpdate failed"}'
    )


def test_matched_dispatch_without_response_spec_cannot_hide_server_timeout():
    contract = {"requirements": [{"id": "query", "minimum_dispatches": 1}]}
    event = {"kind": "scenario", "status": 504, "matched_requirements": ["query"]}
    assert not verify_responses(contract, [event])["passed"]
    assert not verify_responses(contract, [{**event, "status": 500}])["passed"]
    assert verify_responses(contract, [{**event, "status": 200}])["passed"]


def test_mixed_graphql_requires_every_ordered_result_without_errors():
    spec = {
        "content_type": "application/json",
        "graphql_response_fields": ["systemUpdate", "systemHealth", "pastes"],
    }
    good = '[{"data":{"systemUpdate":"done"}},{"data":{"systemHealth":"healthy"}},{"data":{"pastes":[]}}]'
    assert response_content_matches(spec, "application/json", good)
    assert not response_content_matches(
        spec, "application/json", '[{"data":{"systemUpdate":"done"}}]'
    )
    assert not response_content_matches(
        spec, "application/json", good.replace('"pastes":[]', '"wrong":[]')
    )
    assert not response_content_matches(
        spec,
        "application/json",
        good.replace('"systemHealth":"healthy"', '"systemHealth":null'),
    )
    assert not response_content_matches(
        spec,
        "application/json",
        good.replace(
            '{"data":{"pastes":[]}}',
            '{"data":{"pastes":[]},"errors":[{"message":"failed"}]}',
        ),
    )


def test_declared_native_403_requires_application_identity_and_is_not_waap_proof():
    requirement = {
        "id": "conversion",
        "minimum_dispatches": 1,
        "expected_statuses": [403],
        "response_contract_by_status": {"403": {"content_type": "application/json"}},
    }
    event = {
        "kind": "scenario",
        "status": 403,
        "matched_requirements": ["conversion"],
        "response_assertions": {"conversion": False},
    }
    assert not verify_responses({"requirements": [requirement]}, [event])["passed"]
    event["response_assertions"]["conversion"] = True
    assert verify_responses({"requirements": [requirement]}, [event])["passed"]
    assert (
        classify_outcome({**event, "status_specific_assertions": {"conversion": True}})
        == "expected_application_rejection"
    )
    assert (
        classify_outcome({**event, "status_specific_assertions": {"conversion": False}})
        == "mitigation_candidate"
    )
