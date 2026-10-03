"""Precise scenario contracts reject setup, wrong payloads and missing actions."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_dispatch import (  # noqa: E402
    classify_outcome,
    match_requirements,
    validate_dispatch_contract,
    verify_dispatch,
    verify_responses,
)


def contract():
    """Two distinct endpoint and payload actions are mandatory."""
    return {
        "requirements": [
            {
                "id": "malformed-json",
                "method": "POST",
                "path": "/vampi/users/v1/register",
                "body_exact": '{"username":',
                "minimum_dispatches": 1,
                "payload_class": "malformed-json",
            },
            {
                "id": "deny",
                "method": "POST",
                "path": "/httpbin/anything/admin",
                "body_exact": '{"op":"escalate"}',
                "minimum_dispatches": 3,
                "payload_class": "endpoint-denial",
            },
        ]
    }


def test_wrong_method_body_or_setup_cannot_match():
    """Setup and superficially similar requests cannot satisfy attack launches."""
    specification = contract()
    request = {
        "kind": "scenario",
        "method": "POST",
        "path": "/vampi/users/v1/register",
        "body": '{"username":',
        "query": "",
    }
    assert match_requirements(specification, request) == ["malformed-json"]
    assert not match_requirements(specification, dict(request, kind="prerequisite"))
    assert not match_requirements(specification, dict(request, method="GET"))
    assert not match_requirements(
        specification, dict(request, body='{"username":"seed"}')
    )


def test_all_requirements_and_dispatch_counts_are_mandatory():
    """One matching endpoint cannot substitute for the other declared actions."""
    specification = contract()
    events = [{"kind": "scenario", "matched_requirements": ["malformed-json"]}]
    assert not verify_dispatch(specification, events)["passed"]
    events += [{"kind": "scenario", "matched_requirements": ["deny"]}] * 3
    assert verify_dispatch(specification, events)["passed"]
    assert not verify_dispatch(
        specification, [dict(event, kind="filler") for event in events]
    )["passed"]


def test_payload_classes_are_verified_before_redacted_event_storage():
    """Class matching does not depend on copying credentials into receipts."""
    specification = {
        "requirements": [
            {
                "id": "query",
                "method": "GET",
                "path_regex": r"/vampi/users/v1/[^/]+",
                "query_regex": r"(?:^|&)id=",
                "minimum_dispatches": 1,
                "payload_class": "query-parameter",
            }
        ]
    }
    assert match_requirements(
        specification,
        {
            "kind": "scenario",
            "method": "GET",
            "path": "/vampi/users/v1/name1",
            "query": "id=1",
            "body": "",
        },
    ) == ["query"]
    assert not match_requirements(
        specification,
        {
            "kind": "scenario",
            "method": "GET",
            "path": "/vampi/users/v1/name1",
            "query": "",
            "body": "",
        },
    )


def test_requirement_match_checks_declared_header_and_query():
    """Correct endpoint and body without required request properties cannot pass."""
    specification = {
        "requirements": [
            {
                "id": "typed",
                "method": "POST",
                "path": "/httpbin/post",
                "headers": {"content-type": "application/json"},
                "query_regex": r"^fixture=synthetic$",
                "minimum_dispatches": 1,
                "payload_class": "typed-json",
            }
        ]
    }
    event = {
        "kind": "scenario",
        "method": "POST",
        "path": "/httpbin/post",
        "headers": {"content-type": "application/json"},
        "query": "fixture=synthetic",
    }
    assert match_requirements(specification, event) == ["typed"]
    assert not match_requirements(specification, dict(event, headers={}))
    assert not match_requirements(specification, dict(event, query=""))


def test_graphql_contract_rejects_invalid_json_and_other_operations():
    """Query tokens alone do not prove a valid dispatched GraphQL document."""
    specification = {
        "requirements": [
            {
                "id": "mutation",
                "method": "POST",
                "path": "/dvga/graphql",
                "graphql_operation": r"createPaste\(",
                "minimum_dispatches": 1,
                "payload_class": "stored-xss",
            }
        ]
    }
    event = {
        "kind": "scenario",
        "method": "POST",
        "path": "/dvga/graphql",
        "body": json.dumps(
            {"query": 'mutation{createPaste(title:"synthetic"){paste{id}}}'}
        ),
    }
    assert match_requirements(specification, event) == ["mutation"]
    assert not match_requirements(
        specification, dict(event, body='{"query":"createPaste("')
    )
    assert not match_requirements(
        specification, dict(event, body='{"query":"{pastes{id}}"}')
    )


def test_invalid_contracts_fail_before_execution():
    """Empty or duplicated requirements cannot silently become passing contracts."""
    with pytest.raises(ValueError, match="at least one action"):
        validate_dispatch_contract({"requirements": []})
    item = {
        "id": "same",
        "method": "GET",
        "path": "/httpbin/get",
        "minimum_dispatches": 1,
        "payload_class": "probe",
    }
    with pytest.raises(ValueError, match="unique"):
        validate_dispatch_contract({"requirements": [item, item]})


def test_status_classification_does_not_label_unattributed_403_as_proven_mitigation():
    """WAAP denial candidates, application errors and transport failures stay distinct."""
    assert classify_outcome({"status": 403}) == "mitigation_candidate"
    assert (
        classify_outcome({"status": 404, "expected_statuses": [404]})
        == "expected_application_response"
    )
    assert classify_outcome({"status": 404}) == "unexpected_application_response"
    assert (
        classify_outcome({"status": 500, "expected_statuses": [500]})
        == "expected_application_response"
    )
    assert classify_outcome({"status": 502}) == "unexpected_application_response"
    assert classify_outcome({"transport_error": "TimeoutError"}) == "transport_failure"


def test_unauthenticated_probe_cannot_be_satisfied_by_authenticated_setup():
    """BOLA no-auth contracts require the actual absence of an authorization header."""
    specification = {
        "requirements": [
            {
                "id": "unauth",
                "method": "GET",
                "path": "/crapi/workshop/api/shop/orders/1",
                "absent_headers": ["authorization"],
                "minimum_dispatches": 1,
                "payload_class": "unauthenticated-order",
            }
        ]
    }
    request = {
        "kind": "scenario",
        "method": "GET",
        "path": "/crapi/workshop/api/shop/orders/1",
        "headers": {},
    }
    assert match_requirements(specification, request) == ["unauth"]
    assert not match_requirements(
        specification, dict(request, headers={"authorization": "Bearer synthetic"})
    )


def test_exact_decoded_query_contract_rejects_filler_and_changed_payload():
    """Every SQL expression requires its exact decoded parameter, not a broad regex."""
    specification = {
        "requirements": [
            {
                "id": "union",
                "method": "GET",
                "path": "/juice-shop/rest/products/search",
                "query_values": {"q": "test'))UNION SELECT '1'--"},
                "minimum_dispatches": 1,
                "payload_class": "sql-union",
            }
        ]
    }
    event = {
        "kind": "scenario",
        "method": "GET",
        "path": "/juice-shop/rest/products/search",
        "query": "q=test",
    }
    assert not match_requirements(specification, event)
    event["query"] = "q=test%27%29%29UNION%20SELECT%20%271%27--"
    assert match_requirements(specification, event) == ["union"]
    assert not match_requirements(specification, dict(event, kind="prerequisite"))


def test_binary_payload_contract_does_not_accept_decoded_replacement_characters():
    """Invalid UTF-8 offerings must match bytes, not a lossy decoded string."""
    specification = {
        "requirements": [
            {
                "id": "overlong",
                "method": "POST",
                "path": "/",
                "body_hex": "713dc0af",
                "minimum_dispatches": 1,
                "payload_class": "overlong-utf8",
            }
        ]
    }
    event = {
        "kind": "scenario",
        "method": "POST",
        "path": "/",
        "body": "q=�/",
        "body_hex": "713defbfbd2f",
    }
    assert not match_requirements(specification, event)
    event["body_hex"] = "713dc0af"
    assert match_requirements(specification, event) == ["overlong"]


def test_matched_request_requires_declared_response_or_mitigation():
    specification = {
        "requirements": [{"id": "actual-api", "expected_statuses": [200, 401]}]
    }
    event = {"kind": "scenario", "matched_requirements": ["actual-api"], "status": 404}
    assert not verify_responses(specification, [event])["passed"]
    assert verify_responses(specification, [dict(event, status=401)])["passed"]
    assert verify_responses(specification, [dict(event, status=403)])["passed"]
    assert not verify_responses(
        specification, [dict(event, transport_error="timeout")]
    )["passed"]


def test_every_declared_dispatch_requires_a_terminal_response():
    specification = {
        "requirements": [
            {"id": "payload", "minimum_dispatches": 3, "expected_statuses": [200]}
        ]
    }
    event = {"kind": "scenario", "matched_requirements": ["payload"], "status": 200}
    assert not verify_responses(specification, [event])["passed"]
    assert verify_responses(specification, [event] * 3)["passed"]


def test_unmatched_application_error_cannot_be_hidden_by_one_matching_payload():
    specification = {
        "requirements": [
            {"id": "payload", "minimum_dispatches": 1, "expected_statuses": [200]}
        ],
        "reject_unmatched_errors": True,
    }
    event = {"kind": "scenario", "matched_requirements": ["payload"], "status": 200}
    unknown = {"kind": "scenario", "matched_requirements": [], "status": 502}
    assert not verify_responses(specification, [event, unknown])["passed"]


def test_graphql_batch_requires_exact_size_and_declared_operations():
    requirement = {
        "id": "batch",
        "method": "POST",
        "path": "/dvga/graphql",
        "json_body_type": "array",
        "json_array_length": 2,
        "graphql_batch_operation": r"^\{systemUpdate\}$",
    }
    request = {
        "kind": "scenario",
        "method": "POST",
        "path": "/dvga/graphql",
        "body": '[{"query":"{systemUpdate}"},{"query":"{systemUpdate}"}]',
    }
    assert match_requirements({"requirements": [requirement]}, request) == ["batch"]
    request["body"] = '[{"query":"{__typename}"},{"query":"{__typename}"}]'
    assert not match_requirements({"requirements": [requirement]}, request)
    request["body"] = '[{"query":"{systemUpdate}"}]'
    assert not match_requirements({"requirements": [requirement]}, request)
