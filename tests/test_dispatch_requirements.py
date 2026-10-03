"""Precise scenario contracts reject setup, wrong payloads and missing actions."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_dispatch import match_requirements, verify_dispatch  # noqa: E402


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
