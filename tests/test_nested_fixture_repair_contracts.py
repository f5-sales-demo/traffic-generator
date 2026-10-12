"""Native child setup must match its declared tool and mutation contracts."""

import json
from pathlib import Path

from traffic_dispatch import (
    match_requirements,
    response_content_matches,
    verify_responses,
)
from traffic_native_identity import native_identity

ROOT = Path(__file__).resolve().parents[1]


def test_mutating_restaurant_children_have_journal_adapter():
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    for identifier in (
        "restaurant-exploits/07-command-injection",
        "restaurant-exploits/09-jwt-secret-crack",
    ):
        scenario = next(row for row in scenarios if row["id"] == identifier)
        assert scenario["adapter"] == "native-family-journal"
        assert scenario["fixture_contract"]["family_restore"] == "restaurant"
        assert (
            scenario["functional_contract"]["mutation_policy"]
            == "journaled-restoration"
        )


def test_dalfox_v3_uses_required_target_option_for_both_native_scans():
    source = (ROOT / "suites/web-app-attacks/02-xss.sh").read_text()
    assert source.count('dalfox url --url "${BASE}') == 2
    assert "--silence --no-color --timeout 10" in source


def test_native_sql_errors_are_exact_per_payload_and_reject_other_server_failures():
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    for identifier, requirement, title in (
        (
            "web-app-attacks/01-sqli",
            "payload-4-target-0",
            "<title>Error: SQLITE_ERROR: incomplete input</title>",
        ),
        (
            "web-app-attacks/02-xss",
            "payload-5-target-0",
            "<title>Error: SQLITE_ERROR: near &quot;XSS&quot;: syntax error</title>",
        ),
    ):
        scenario = next(row for row in scenarios if row["id"] == identifier)
        row = next(
            row
            for row in scenario["dispatch_contract"]["requirements"]
            if row["id"] == requirement
        )
        contract = row["response_contract_by_status"]["500"]
        assert response_content_matches(contract, "text/html", title)
        assert not response_content_matches(
            contract, "text/html", "<title>Server Error</title>"
        )
        event = {
            "kind": "scenario",
            "status": 500,
            "matched_requirements": [requirement],
            "response_assertions": {requirement: True},
        }
        assert verify_responses({"requirements": [row]}, [event])["passed"]
        event["response_assertions"] = {requirement: False}
        assert not verify_responses({"requirements": [row]}, [event])["passed"]


def test_restaurant_response_identity_is_route_and_shape_bound():
    output = json.dumps({"output": "Filesystem synthetic native output"})
    assert native_identity(
        "/restaurant/admin/stats/disk", "GET", 200, "application/json", output
    )
    assert not native_identity(
        "/restaurant/profile", "GET", 200, "application/json", output
    )
    assert not native_identity(
        "/restaurant/admin/stats/disk",
        "GET",
        200,
        "application/json",
        '{"output":"unrelated"}',
    )
    debug = json.dumps(
        dict.fromkeys(
            ["os_info", "env_vars", "local_paths", "disk_usage", "memory_usage"],
            "synthetic",
        )
    )
    assert native_identity("/restaurant/debug", "GET", 200, "application/json", debug)
    assert not native_identity(
        "/restaurant/debug", "GET", 200, "application/json", '{"os_info":"synthetic"}'
    )


def test_traversal_query_paths_preserve_native_directory_slash():
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    scenario = next(
        row for row in scenarios if row["id"] == "web-app-attacks/04-path-traversal"
    )
    requirements = [
        row
        for row in scenario["dispatch_contract"]["requirements"]
        if row.get("path", "").startswith("/dvwa/")
    ]
    assert len(requirements) == 19
    assert all(row["path"] == "/dvwa/vulnerabilities/fi/" for row in requirements)


def test_csrf_actor_body_matches_only_marker_owned_synthetic_identity():
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    scenario = next(row for row in scenarios if row["id"] == "web-app-attacks/09-csrf")
    requirement = next(
        row
        for row in scenario["dispatch_contract"]["requirements"]
        if row["id"] == "csrf-7"
    )
    request: dict = {
        "kind": "scenario",
        "method": "POST",
        "path": "/juice-shop/api/Users",
        "body": '{"email":"tgen-'
        + "a" * 32
        + '@example.com","password":"Test1234","passwordRepeat":"Test1234"}',
        "headers": {
            "content-type": "application/json",
            "origin": "http://evil.example",
        },
    }
    assert match_requirements({"requirements": [requirement]}, request) == ["csrf-7"]
    request["body"] = request["body"].replace("tgen-", "foreign-")
    assert not match_requirements({"requirements": [requirement]}, request)
    assert native_identity(
        "/juice-shop/rest/user/whoami", "GET", 200, "application/json", '{"user":{}}'
    )
    assert not native_identity(
        "/juice-shop/rest/user/whoami",
        "GET",
        200,
        "application/json",
        '{"unrelated":{}}',
    )
