"""Native load acceptance requires complete combinations, actual content and cleanup."""

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_dispatch import response_content_matches
from traffic_functional import (
    verify_composed_native,
    verify_csrf,
    verify_functional,
    verify_load,
    verify_scraper,
)
from traffic_security import bot_attribution, waf_attribution


def test_load_rejects_missing_workers_and_wrong_content(tmp_path):
    scenario = {
        "native_load_contract": {
            "tools": ["wrk", "hey"],
            "paths": ["/httpbin/get"],
            "levels": [2],
            "connection_modes": [True, False],
        },
        "functional_contract": {"behavior": "native phases"},
    }
    result = {"outcome": "launched", "dispatch_contract_verified": True}
    workers = [
        {"tool": tool, "path": "/httpbin/get", "concurrency": 2, "persistent": mode}
        for tool in ["wrk", "hey"]
        for mode in [True, False]
    ]
    receipt: dict = {
        "workers": workers,
        "passed": True,
        "cleanup": True,
        "content_checks": [{"passed": True}],
    }
    path = tmp_path / "native-load.json"
    path.write_text(json.dumps(receipt))
    assert verify_load(scenario, result, tmp_path)["passed"]
    receipt["content_checks"][0]["passed"] = False
    path.write_text(json.dumps(receipt))
    assert not verify_load(scenario, result, tmp_path)["passed"]
    receipt["content_checks"][0]["passed"] = True
    receipt["workers"].pop()
    path.write_text(json.dumps(receipt))
    assert not verify_load(scenario, result, tmp_path)["passed"]


def composed_fixture():
    scenario = {
        "id": "synthetic/read",
        "dispatch_contract": {
            "requirements": [
                {
                    "id": "read",
                    "method": "GET",
                    "path": "/vampi/users/v1",
                    "expected_statuses": [200],
                    "minimum_dispatches": 1,
                }
            ]
        },
        "functional_contract": {
            "behavior": "native read",
            "mutation_policy": "read-only",
        },
    }
    result = {
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    event = {
        "kind": "scenario",
        "scenario": scenario["id"],
        "method": "GET",
        "path": "/vampi/users/v1",
        "status": 200,
        "matched_requirements": ["read"],
        "native_response_identity": True,
        "upstream_dispatched": True,
    }
    return scenario, result, event


def test_composed_rejects_unattributed_denial(tmp_path):
    scenario, result, event = composed_fixture()
    assert verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    event["status"] = 403
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]


def test_composed_rejects_unexpected_status_or_undispatched_response(tmp_path):
    scenario, result, event = composed_fixture()
    event["status"] = 503
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    event["status"] = 200
    event["upstream_dispatched"] = False
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]


def test_composed_restoration_label_requires_observed_recovery(tmp_path):
    scenario, result, event = composed_fixture()
    scenario["functional_contract"]["mutation_policy"] = "journaled-restoration"
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    scenario["functional_contract"]["restoration_fields"] = [
        "video_restoration",
        "otp_restoration",
    ]
    result["video_restoration"] = True
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    result["otp_restoration"] = True
    assert verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    scenario["functional_contract"]["mutation_policy"] = "rehearsal-reset"
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]


def test_report_functional_acceptance_uses_current_dependency_receipts(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "child.sh").write_text("synthetic source")
    catalog = {"scenarios": [{"id": "synthetic/child", "entrypoint": "child.sh"}]}
    (source / "suites").mkdir()
    (source / "suites/catalog.json").write_text(json.dumps(catalog))
    active = tmp_path / "pass-current"
    directory = active / "synthetic--report"
    directory.mkdir(parents=True)
    child = active / "synthetic--child"
    child.mkdir()
    receipt = {
        "id": "synthetic/child",
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "functional_verified": True,
        "source_sha256": hashlib.sha256((source / "child.sh").read_bytes()).hexdigest(),
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
    }
    path = child / "receipt.json"
    path.write_text(json.dumps(receipt))
    scenario = {
        "id": "synthetic/report",
        "report_contract": {"dependencies": ["synthetic/child"]},
        "functional_contract": {
            "verifier": "current-pass-report",
            "behavior": "current dependency outcomes",
        },
    }
    result = {
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
    }
    with patch("traffic_functional.SOURCE_ROOT", source):
        assert verify_functional(scenario, result, [], directory)["passed"]
        receipt["functional_verified"] = False
        path.write_text(json.dumps(receipt))
        assert not verify_functional(scenario, result, [], directory)["passed"]
        receipt["functional_verified"] = True
        receipt["source_commit"] = "c" * 40
        path.write_text(json.dumps(receipt))
        assert not verify_functional(scenario, result, [], directory)["passed"]


def test_discovery_requires_native_report_identity_and_observed_cleanup(tmp_path):
    scenario = {
        "id": "reconnaissance/05-subfinder-enum",
        "functional_contract": {
            "verifier": "native-subfinder",
            "behavior": "passive discovery",
        },
    }
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "outcome": "launched",
        "dispatch_contract_verified": True,
    }
    report = tmp_path / "subfinder-native.jsonl"
    report.write_text('{"host":"api.example.com","source":"crtsh"}\n')
    evidence: dict = {
        "scenario": scenario["id"],
        "execution": "native-subfinder",
        "passed": True,
        "source_commit": result["source_commit"],
        "artifact_sha256": result["artifact_sha256"],
        "authorized_domain": "example.com",
        "discoveries": 1,
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "binary_sha256": "c" * 64,
        "process": {
            "exit_code": 0,
            "timed_out": False,
            "observed_process_count": 1,
            "connections_closed": True,
            "remaining_after_cleanup": [],
        },
    }
    receipt = tmp_path / "native-discovery.json"
    receipt.write_text(json.dumps(evidence))
    assert verify_functional(scenario, result, [], tmp_path)["passed"]
    report.write_text('{"host":"foreign.invalid","source":"crtsh"}\n')
    evidence["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    receipt.write_text(json.dumps(evidence))
    assert not verify_functional(scenario, result, [], tmp_path)["passed"]
    report.write_text('{"host":"api.example.com","source":"crtsh"}\n')
    evidence["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    evidence["process"]["timed_out"] = True
    receipt.write_text(json.dumps(evidence))
    assert not verify_functional(scenario, result, [], tmp_path)["passed"]


def test_native_routes_require_all_rendered_actions_screenshots_and_cleanup(tmp_path):
    scenario = {
        "id": "bot-simulation/04-rapid-browsing",
        "route_contract": {"actions": ["ua-0-route-0"]},
        "functional_contract": {
            "verifier": "native-browser-routes",
            "behavior": "native rendered route",
        },
    }
    result = {
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    image = tmp_path / "ua-0-route-0.png"
    image.write_bytes(bytes.fromhex("89504e470d0a1a0a") + b"synthetic")
    receipt: dict = {
        "scenario": scenario["id"],
        "source_commit": result["source_commit"],
        "artifact_sha256": result["artifact_sha256"],
        "actions": [
            {
                "id": "ua-0-route-0",
                "performed": True,
                "rendered": True,
                "status": 200,
                "urlMatches": True,
                "contentMatches": True,
            }
        ],
        "browser_closed": True,
    }
    p = tmp_path / "route-actions.json"
    p.write_text(json.dumps(receipt))
    assert verify_functional(scenario, result, [], tmp_path)["passed"]
    image.unlink()
    assert not verify_functional(scenario, result, [], tmp_path)["passed"]
    image.write_bytes(bytes.fromhex("89504e470d0a1a0a"))
    receipt["browser_closed"] = False
    p.write_text(json.dumps(receipt))
    assert not verify_functional(scenario, result, [], tmp_path)["passed"]
    receipt["browser_closed"] = True
    receipt["actions"][0].update(rendered=False, mitigated=True, status=403)
    p.write_text(json.dumps(receipt))
    assert not verify_functional(scenario, result, [], tmp_path)["passed"]


def test_bot_denial_requires_exact_request_security_and_effective_firewall(tmp_path):
    response: dict = {
        "scenario": "bot-simulation/04-rapid-browsing",
        "domain": "www.example.com",
        "path": "/juice-shop/",
        "method": "GET",
        "status": 403,
        "synthetic_identity": "showcase-" + "a" * 32 + "-rapid-ua-3",
        "sent_at": 10.0,
        "received_at": 11.0,
        "upstream_dispatched": True,
        "payload_sha256": "a" * 64,
        "response_sha256": "b" * 64,
    }
    action = {
        "id": "ua-3-route-0",
        "performed": True,
        "rendered": False,
        "mitigated": True,
        "status": 403,
        "fresh_document_response": True,
    }
    event = {
        "req_id": "synthetic-request",
        "namespace": "example-waap",
        "vh_name": "ves-io-http-loadbalancer-example-waap",
        "domain": "www.example.com",
        "req_path": "/juice-shop/",
        "method": "GET",
        "user": "Header-X-Mud-User-" + response["synthetic_identity"],
        "time": "1970-01-01T00:00:10.500Z",
        "rsp_code": "403",
        "action": "block",
        "sec_event_type": "waf_sec_event",
        "sec_event_name": "WAF",
        "app_firewall_name": "example-waap-waf",
        "enforcement_mode": "Blocking",
        "waf_mode": "block",
        "recommended_action": "block",
        "bot_info": {
            "classification": "malicious",
            "anomaly": "Search Engine Verification Failed",
            "type": "Search Engine",
            "name": "Google",
        },
    }
    access = {**event}
    evidence: dict = {
        "source_commit": "c" * 40,
        "artifact_sha256": "d" * 64,
        "scope": {
            "namespace": "example-waap",
            "loadbalancer": "example-waap",
            "domain": "www.example.com",
        },
        "clock_bounds": [-1, 1],
        "firewall": {
            "metadata": {"name": "example-waap-waf", "namespace": "example-waap"},
            "spec": {"blocking": {}, "default_bot_setting": {}},
        },
        "checks": [
            {
                "response": response,
                "action_id": action["id"],
                "access": access,
                "events": [event],
            }
        ],
    }
    result = {"source_commit": "c" * 40, "artifact_sha256": "d" * 64}
    (tmp_path / "control-attribution.json").write_text(json.dumps(evidence))
    assert bot_attribution(action, response, result, tmp_path)
    event["req_id"] = "foreign-request"
    (tmp_path / "control-attribution.json").write_text(json.dumps(evidence))
    assert not bot_attribution(action, response, result, tmp_path)
    event["req_id"] = "synthetic-request"
    evidence["firewall"]["spec"] = {"monitoring": {}}
    (tmp_path / "control-attribution.json").write_text(json.dumps(evidence))
    assert not bot_attribution(action, response, result, tmp_path)


def test_graphql_read_contracts_require_native_data_not_generic_errors():
    contract = {
        "content_type": "application/json",
        "graphql_list_field": "pastes",
        "graphql_list_fields": ["title"],
    }
    assert response_content_matches(
        contract, "application/json", '{"data":{"pastes":[{"title":"synthetic"}]}}'
    )
    assert not response_content_matches(
        contract, "application/json", '{"errors":[{"message":"wrong query"}]}'
    )
    assert not response_content_matches(
        contract, "application/json", '{"data":{"pastes":[]}}'
    )
    assert not response_content_matches(
        contract, "application/json", '{"data":{"pastes":[{"unrelated":true}]}}'
    )


def test_scraper_requires_every_native_page_receipt_and_cleanup(tmp_path):
    scenario = {
        "id": "bot-simulation/02-puppeteer-scraper",
        "scrape_contract": {"paths": ["/vampi/"]},
        "functional_contract": {"behavior": "native scraping"},
    }
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    image = tmp_path / "scrape-0.png"
    image.write_bytes(bytes.fromhex("89504e470d0a1a0a"))
    evidence = {
        "scenario": scenario["id"],
        "source_commit": result["source_commit"],
        "artifact_sha256": result["artifact_sha256"],
        "browser_closed": True,
        "actions": [
            {
                "path": "/vampi/",
                "passed": True,
                "status": 200,
                "content_matches": True,
                "screenshot": "scrape-0.png",
                "response_sha256": "c" * 64,
            }
        ],
    }
    p = tmp_path / "scraper-functional.json"
    p.write_text(json.dumps(evidence))
    assert verify_scraper(scenario, result, tmp_path)["passed"]
    evidence["actions"] = []
    p.write_text(json.dumps(evidence))
    assert not verify_scraper(scenario, result, tmp_path)["passed"]
    evidence["browser_closed"] = False
    p.write_text(json.dumps(evidence))
    assert not verify_scraper(scenario, result, tmp_path)["passed"]


def test_csrf_acceptance_requires_mutation_fresh_login_and_recovery(tmp_path):
    s = {"functional_contract": {"behavior": "native CSRF"}}
    r = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    d = {
        "source_commit": r["source_commit"],
        "artifact_sha256": r["artifact_sha256"],
        "actor": "tgen_csrf",
        "changed": True,
        "fresh_login": True,
        "restored": True,
    }
    p = tmp_path / "csrf-restoration.json"
    p.write_text(json.dumps(d))
    assert verify_csrf(s, r, tmp_path)["passed"]
    d["fresh_login"] = False
    p.write_text(json.dumps(d))
    assert not verify_csrf(s, r, tmp_path)["passed"]


def test_composed_requires_declared_content_assertion_even_with_native_identity(
    tmp_path,
):
    scenario, result, event = composed_fixture()
    scenario["dispatch_contract"]["requirements"][0]["response_contract"] = {
        "content_type": "application/json",
        "json_keys": ["users"],
    }
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    event["response_assertions"] = {"read": True}
    assert verify_composed_native(scenario, result, [event], tmp_path)["passed"]


def test_native_mechanic_shape_uses_nested_objects_and_string_identity():
    contract = {
        "content_type": "application/json",
        "json_nonempty_lists": {"mechanics": ["mechanic_code"]},
        "json_nested_list_matches": {
            "mechanics": {"user.email": r"[A-Za-z0-9._%+-]+@example\.com"}
        },
    }
    body = {
        "mechanics": [
            {
                "id": 1,
                "mechanic_code": "TRAC_EXAMPLE",
                "user": {"email": "mechanic@example.com"},
            }
        ]
    }
    assert response_content_matches(contract, "application/json", json.dumps(body))
    body["mechanics"][0]["user"] = {}
    assert not response_content_matches(contract, "application/json", json.dumps(body))


def test_waf_signature_requires_exact_request_and_enabled_signature(tmp_path):
    response: dict = {
        "scenario": "bot-simulation/04-rapid-browsing",
        "domain": "www.example.com",
        "path": "/juice-shop/",
        "method": "GET",
        "status": 403,
        "synthetic_identity": "showcase-" + "a" * 32 + "-rapid-ua-3",
        "sent_at": 10.0,
        "received_at": 11.0,
        "upstream_dispatched": True,
        "payload_sha256": "a" * 64,
        "response_sha256": "b" * 64,
    }
    action = {
        "id": "ua-3-route-0",
        "performed": True,
        "rendered": False,
        "mitigated": True,
        "status": 403,
        "fresh_document_response": True,
    }
    event = {
        "req_id": "synthetic-request",
        "namespace": "example-waap",
        "vh_name": "ves-io-http-loadbalancer-example-waap",
        "domain": "www.example.com",
        "req_path": "/juice-shop/",
        "method": "GET",
        "user": "Header-X-Mud-User-" + response["synthetic_identity"],
        "time": "1970-01-01T00:00:10.500Z",
        "rsp_code": "403",
        "action": "block",
        "sec_event_type": "waf_sec_event",
        "sec_event_name": "WAF",
        "app_firewall_name": "example-waap-waf",
        "enforcement_mode": "Blocking",
        "waf_mode": "block",
        "recommended_action": "block",
        "bot_info": {
            "classification": "malicious",
            "anomaly": "Search Engine Verification Failed",
            "type": "Search Engine",
            "name": "Google",
        },
    }
    event["signatures"] = [{"id": "200003915", "state": "Enabled"}]
    access = {**event}
    evidence: dict = {
        "source_commit": "c" * 40,
        "artifact_sha256": "d" * 64,
        "scope": {
            "namespace": "example-waap",
            "loadbalancer": "example-waap",
            "domain": "www.example.com",
        },
        "clock_bounds": [-1, 1],
        "firewall": {
            "metadata": {"name": "example-waap-waf", "namespace": "example-waap"},
            "spec": {"blocking": {}, "default_bot_setting": {}},
        },
        "checks": [
            {
                "response": response,
                "action_id": action["id"],
                "access": access,
                "events": [event],
            }
        ],
    }
    result = {"source_commit": "c" * 40, "artifact_sha256": "d" * 64}
    (tmp_path / "control-attribution.json").write_text(json.dumps(evidence))
    assert waf_attribution(response, result, tmp_path, ["200003915"])
    event["req_id"] = "foreign-request"
    (tmp_path / "control-attribution.json").write_text(json.dumps(evidence))
    assert not waf_attribution(response, result, tmp_path, ["200003915"])
    event["req_id"] = "synthetic-request"
    evidence["firewall"]["spec"] = {"monitoring": {}}
    (tmp_path / "control-attribution.json").write_text(json.dumps(evidence))
    assert not waf_attribution(response, result, tmp_path, ["200003915"])


def test_direct_native_api_requires_nested_content_and_observed_response(tmp_path):
    scenario = {
        "id": "synthetic/community",
        "kind": "shell",
        "functional_contract": {
            "verifier": "direct-native-api",
            "behavior": "synthetic author exposure",
            "mutation_policy": "read-only",
            "native_response_requirements": ["posts"],
        },
        "dispatch_contract": {
            "requirements": [
                {
                    "id": "posts",
                    "method": "GET",
                    "expected_statuses": [200],
                    "response_contract": {
                        "content_type": "application/json",
                        "json_nested_list_matches": {
                            "posts": {"author.email": "example"}
                        },
                    },
                }
            ],
        },
    }
    result = {
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    row: dict = {
        "scenario": scenario["id"],
        "kind": "scenario",
        "matched_requirements": ["posts"],
        "status": 200,
        "upstream_dispatched": True,
        "response_assertions": {"posts": True},
    }
    assert verify_functional(scenario, result, [row], tmp_path)["passed"]
    row["response_assertions"]["posts"] = False
    assert not verify_functional(scenario, result, [row], tmp_path)["passed"]
    assert not verify_functional(scenario, result, [], tmp_path)["passed"]


def test_weak_session_requires_all_native_cookie_values(tmp_path):
    scenario = {
        "id": "dvwa-exploits/12-weak-session",
        "functional_contract": {
            "verifier": "native-dvwa-weak-session",
            "behavior": "native predictable cookies",
        },
    }
    result = {
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
    }
    rows = [
        {
            "scenario": scenario["id"],
            "kind": "scenario",
            "matched_requirements": ["generate"],
            "native_session_id": str(index),
            "status": 200,
            "upstream_dispatched": True,
        }
        for index in range(20)
    ]
    assert verify_functional(scenario, result, rows, tmp_path)["passed"]
    rows[-1]["native_session_id"] = "unobserved"
    assert not verify_functional(scenario, result, rows, tmp_path)["passed"]
    assert not verify_functional(scenario, result, rows[:1], tmp_path)["passed"]


def test_dvwa_corpus_rejects_missing_payload_or_wrong_native_content(tmp_path):
    scenario = {
        "id": "synthetic/corpus",
        "dispatch_contract": {"payloads": ["one", "two"]},
        "functional_contract": {
            "verifier": "native-dvwa-corpus",
            "behavior": "native corpus",
            "waf_signatures": [],
        },
    }
    result = {"outcome": "launched", "dispatch_contract_verified": True}
    rows: list[dict] = [
        {
            "scenario": scenario["id"],
            "kind": "scenario",
            "status": 200,
            "upstream_dispatched": True,
            "native_body_verified": True,
            "corpus_payload_sha256": hashlib.sha256(value.encode()).hexdigest(),
        }
        for value in ["one", "two"]
    ]
    assert verify_functional(scenario, result, rows, tmp_path)["passed"]
    assert not verify_functional(scenario, result, rows[:1], tmp_path)["passed"]
    rows[0]["native_body_verified"] = False
    assert not verify_functional(scenario, result, rows, tmp_path)["passed"]


def test_composed_accepts_only_prevalidated_control_attribution(tmp_path):
    scenario, result, event = composed_fixture()
    event.update(status=403, native_response_identity=False)
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    event["control_attributed"] = True
    assert verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    event["upstream_dispatched"] = False
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]


def test_orders_require_nested_native_data_and_real_positive_exposure(tmp_path):
    scenario, result, event = composed_fixture()
    scenario["functional_contract"].update(verifier="native-crapi-orders")
    requirement = scenario["dispatch_contract"]["requirements"][0]
    requirement["id"] = "unauthenticated-order"
    requirement["response_contract"] = {
        "content_type": "application/json",
        "json_nested_keys": {"order": ["id", "user"], "order.user": ["email"]},
    }
    assert response_content_matches(
        requirement["response_contract"],
        "application/json",
        '{"order":{"id":1,"user":{"email":"synthetic@example.com"}}}',
    )
    assert not response_content_matches(
        requirement["response_contract"],
        "application/json",
        '{"order":{"id":1,"user":{}}}',
    )
    event.update(
        matched_requirements=["unauthenticated-order"],
        response_assertions={"unauthenticated-order": True},
    )
    assert verify_functional(scenario, result, [event], tmp_path)["passed"]
    requirement["expected_statuses"] = [500]
    event["status"] = 500
    assert not verify_functional(scenario, result, [event], tmp_path)["passed"]


def test_nested_functional_requires_each_source_bound_child_and_cleanup(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "suites").mkdir()
    (source / "child.sh").write_text("synthetic child")
    (source / "suites/catalog.json").write_text(
        json.dumps({"scenarios": [{"id": "synthetic/child", "entrypoint": "child.sh"}]})
    )
    child = tmp_path / "nested-synthetic/synthetic--child"
    child.mkdir(parents=True)
    receipt = {
        "id": "synthetic/child",
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "source_sha256": hashlib.sha256((source / "child.sh").read_bytes()).hexdigest(),
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "functional_verified": True,
    }
    path = child / "receipt.json"
    path.write_text(json.dumps(receipt))
    scenario = {
        "functional_contract": {
            "verifier": "native-nested-suites",
            "behavior": "native child recovery",
        },
        "nested_contract": {"synthetic": ["synthetic/child"]},
    }
    replicas: dict = {
        family + "-" + str(i): {}
        for family in ["vampi", "dvwa", "restaurant", "juice-shop", "dvga"]
        for i in range(1, 5)
    }
    family = {
        "family": "mixed",
        "identity": "e" * 32,
        "marker": "tgen-" + "e" * 32,
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "replicas": replicas,
    }
    (tmp_path / "family-baseline.json").write_text(json.dumps(family))
    (tmp_path / "family-restoration.json").write_text(
        json.dumps({**family, "restored": True, "after": replicas})
    )
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    with patch("traffic_functional.SOURCE_ROOT", source):
        assert verify_functional(scenario, result, [], tmp_path)["passed"]
        receipt["functional_verified"] = False
        path.write_text(json.dumps(receipt))
        assert not verify_functional(scenario, result, [], tmp_path)["passed"]
        receipt["functional_verified"] = True
        receipt["source_commit"] = "c" * 40
        path.write_text(json.dumps(receipt))
        assert not verify_functional(scenario, result, [], tmp_path)["passed"]


def test_corpus_setup_response_cannot_invalidate_or_satisfy_payload_coverage(tmp_path):
    scenario = {
        "id": "synthetic/corpus",
        "dispatch_contract": {"payloads": ["payload"]},
        "functional_contract": {
            "verifier": "native-dvwa-corpus",
            "behavior": "payload",
            "waf_signatures": [],
        },
    }
    result = {"outcome": "launched", "dispatch_contract_verified": True}
    setup = {
        "scenario": scenario["id"],
        "kind": "scenario",
        "status": 302,
        "upstream_dispatched": True,
    }
    payload = {
        "scenario": scenario["id"],
        "kind": "scenario",
        "status": 200,
        "upstream_dispatched": True,
        "native_body_verified": True,
        "corpus_payload_sha256": hashlib.sha256(b"payload").hexdigest(),
    }
    assert verify_functional(scenario, result, [setup, payload], tmp_path)["passed"]
    assert not verify_functional(scenario, result, [setup], tmp_path)["passed"]


def test_composed_status_specific_content_cannot_pass_with_native_page_only(tmp_path):
    scenario, result, event = composed_fixture()
    requirement = scenario["dispatch_contract"]["requirements"][0]
    requirement["response_contract_by_status"] = {
        "200": {"content_type": "text/html", "text_contains": ["owned payload"]}
    }
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    event["response_assertions"] = {"read": True}
    assert verify_composed_native(scenario, result, [event], tmp_path)["passed"]
    event["response_assertions"]["read"] = False
    assert not verify_composed_native(scenario, result, [event], tmp_path)["passed"]
