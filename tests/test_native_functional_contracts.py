"""Native load acceptance requires complete combinations, actual content and cleanup."""

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_functional import verify_composed_native, verify_functional, verify_load


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
