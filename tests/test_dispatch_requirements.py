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
