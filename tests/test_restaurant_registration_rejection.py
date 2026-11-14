"""Native signup conflicts stay separate from request-bound WAAP mitigation."""

import importlib.util
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from mitmproxy import http
from traffic_native_identity import native_identity, restaurant_registration_rejection
from traffic_security import await_control_evidence

BODY = b'{"detail":"Username or phone number already registered."}'


@pytest.mark.parametrize(
    ("path", "method", "status", "media", "body"),
    [
        ("/restaurant/login", "POST", 403, "application/json", BODY),
        ("/restaurant/register", "GET", 403, "application/json", BODY),
        ("/restaurant/register", "POST", 400, "application/json", BODY),
        ("/restaurant/register", "POST", 403, "text/html", BODY),
        ("/restaurant/register", "POST", 403, "application/json", b"invalid"),
        (
            "/restaurant/register",
            "POST",
            403,
            "application/json",
            b'{"detail":"Forbidden"}',
        ),
        (
            "/restaurant/register",
            "POST",
            403,
            "application/json",
            b'{"detail":"Username or phone number already registered.","blocked":true}',
        ),
    ],
)
def test_rejection_requires_exact_native_route_method_status_and_document(
    path, method, status, media, body
):
    assert not restaurant_registration_rejection(
        path, method, status, media, body.decode()
    )


def test_exact_native_conflict_accepts_json_charset():
    assert restaurant_registration_rejection(
        "/restaurant/register",
        "POST",
        403,
        "application/json; charset=utf-8",
        BODY.decode(),
    )
    assert native_identity(
        "/restaurant/register", "POST", 403, "application/json", BODY.decode()
    )
    assert not native_identity(
        "/restaurant/register",
        "POST",
        403,
        "application/json",
        '{"detail":"Forbidden"}',
    )


def record_response(directory: Path, body: bytes, monkeypatch) -> dict:
    monkeypatch.setenv("TGEN_DOMAINS", '["www.example.test"]')
    monkeypatch.setenv("TGEN_PROXY_METRICS", str(directory / "proxy-metrics.json"))
    spec = importlib.util.spec_from_file_location(
        "registration_response_proxy",
        Path(__file__).parents[1] / "scripts/traffic_proxy.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    budget = module.addons[0]
    flow = SimpleNamespace(
        metadata={
            "tgen_scenario": {
                "id": "cdn-load-testing/09-origin-torture",
                "phase": "execution",
                "dispatch_path": str(directory / "dispatch-events.jsonl"),
            },
            "tgen_upstream_dispatched": True,
        },
        request=http.Request.make(
            "POST", "https://example.com/restaurant/register", content=b"{}"
        ),
        response=http.Response.make(403, body, {"content-type": "application/json"}),
    )
    budget.record_outcome(flow, status=403)
    return json.loads((directory / "response-events.jsonl").read_text())


def test_parent_incidental_conflict_keeps_response_identity_and_skips_waf_wait(
    tmp_path, monkeypatch
):
    row = record_response(tmp_path, BODY, monkeypatch)
    assert row["native_response_identity"] is True
    assert row["matched_requirements"] == []
    assert row["status_specific_assertions"] == {"native-restaurant-registration": True}
    assert row["outcome"] == "expected_application_rejection"
    await_control_evidence({"id": row["scenario"]}, {}, tmp_path, threading.Event())
    assert not (tmp_path / "control-evidence-request.json").exists()


def test_generic_denial_still_requires_request_bound_waap_evidence(
    tmp_path, monkeypatch
):
    row = record_response(tmp_path, b'{"detail":"Forbidden"}', monkeypatch)
    assert row["native_response_identity"] is False
    assert row["status_specific_assertions"] == {}
    assert row["outcome"] == "mitigation_candidate"
    stop = threading.Event()
    stop.set()
    await_control_evidence({"id": row["scenario"]}, {}, tmp_path, stop)
    request = json.loads((tmp_path / "control-evidence-request.json").read_text())
    assert request["requests"] == [row]
