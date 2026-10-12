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


def test_oversize_upload_rejection_is_exact_native_response_and_route_bound():
    body = "<title>413 Request Entity Too Large</title><h1>413 Request Entity Too Large</h1><hr>nginx"
    assert native_identity(
        "/dvwa/vulnerabilities/upload/", "POST", 413, "text/html", body
    )
    assert not native_identity(
        "/dvwa/vulnerabilities/upload/", "POST", 413, "text/html", "generic error"
    )
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    row = next(s for s in scenarios if s["id"] == "web-app-attacks/10-file-upload")[
        "dispatch_contract"
    ]["requirements"][3]
    assert 413 in row["expected_statuses"]
    assert response_content_matches(
        row["response_contract_by_status"]["413"], "text/html", body
    )


def test_empty_native_body_is_exact_and_repeat_delete_requires_missing_object_contract():
    assert response_content_matches({"text_exact": ""}, "", "")
    assert not response_content_matches({"text_exact": ""}, "", "wrong body")
    assert native_identity(
        "/restaurant/admin/stats/disk", "GET", 200, "application/json", '{"output":""}'
    )
    assert not native_identity(
        "/restaurant/admin/stats/disk", "GET", 200, "application/json", "{}"
    )
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    requirement = next(
        row for row in scenarios if row["id"] == "restaurant-exploits/05-bfla-privilege"
    )["dispatch_contract"]["requirements"][0]
    assert 404 in requirement["expected_statuses"]
    assert response_content_matches(
        requirement["response_contract_by_status"]["404"],
        "application/json",
        '{"detail":"Not Found"}',
    )
    assert not response_content_matches(
        requirement["response_contract_by_status"]["404"],
        "application/json",
        '{"detail":"Other"}',
    )


def test_scanner_path_error_contract_requires_native_probe_and_exact_error_title():
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    row = next(r for r in scenarios if r["id"] == "web-app-attacks/02-xss")[
        "dispatch_contract"
    ]["requirements"][0]
    request = {
        "kind": "scenario",
        "method": "GET",
        "path": "/juice-shop/rest/dlxsynthetic/search",
    }
    assert match_requirements({"requirements": [row]}, request) == [
        "native-dalfox-path-discovery"
    ]
    contract = row["response_contract_by_status"]["500"]
    assert response_content_matches(
        contract,
        "text/html",
        "<title>Error: Unexpected path: /rest/dlxsynthetic/search</title>",
    )
    assert not response_content_matches(
        contract, "text/html", "<title>Server Error</title>"
    )
    request["path"] = "/juice-shop/rest/products/search"
    assert not match_requirements({"requirements": [row]}, request)


def test_unicode_traversal_native_denial_is_exact_and_declared_on_one_route():
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    scenario = next(
        r for r in scenarios if r["id"] == "web-app-attacks/04-path-traversal"
    )
    requirement = next(
        r
        for r in scenario["dispatch_contract"]["requirements"]
        if r["id"] == "traversal-13"
    )
    contract = requirement["response_contract_by_status"]["403"]
    body = (
        "<title>Error: Only .md and .pdf files are allowed!</title>"
        "<h1>OWASP Juice Shop (Express ^4.22.1)</h1>"
        "<h2><em>403</em> Error: Only .md and .pdf files are allowed!</h2>"
    )
    assert response_content_matches(contract, "text/html; charset=utf-8", body)
    for wrong in (
        "Forbidden",
        body.replace("403", "500"),
        body.replace("OWASP Juice Shop", "Unknown"),
    ):
        assert not response_content_matches(contract, "text/html", wrong)
    assert not response_content_matches(contract, "application/json", body)
    assert all(
        "403" not in r.get("response_contract_by_status", {})
        for r in scenario["dispatch_contract"]["requirements"]
        if r["id"] != "traversal-13"
    )
    request = {"kind": "scenario", "method": "GET", "path": requirement["path"]}
    assert match_requirements({"requirements": [requirement]}, request) == [
        "traversal-13"
    ]
    request["path"] = "/juice-shop/ftp/etc/passwd"
    assert not match_requirements({"requirements": [requirement]}, request)
    event = {
        "kind": "scenario",
        "status": 403,
        "matched_requirements": ["traversal-13"],
        "response_assertions": {"traversal-13": True},
        "status_specific_assertions": {"traversal-13": True},
        "native_response_identity": True,
    }
    assert verify_responses({"requirements": [requirement]}, [event])["passed"]
    event["response_assertions"] = {"traversal-13": False}
    assert not verify_responses({"requirements": [requirement]}, [event])["passed"]


def test_native_basket_denial_is_exact_single_quoted_response_and_post_route():
    body = "{'error' : 'Invalid BasketId'}"
    assert native_identity(
        "/juice-shop/api/BasketItems/", "POST", 401, "text/html; charset=utf-8", body
    )
    for path, method, status, media, wrong in (
        ("/juice-shop/api/Users/", "POST", 401, "text/html", body),
        ("/juice-shop/api/BasketItems/", "GET", 401, "text/html", body),
        ("/juice-shop/api/BasketItems/", "POST", 403, "text/html", body),
        ("/juice-shop/api/BasketItems/", "POST", 401, "application/json", body),
        ("/juice-shop/api/BasketItems/", "POST", 401, "text/html", "Forbidden"),
    ):
        assert not native_identity(path, method, status, media, wrong)


def test_native_admin_config_version_and_bundle_require_exact_routes_and_shapes():
    config = json.dumps(
        {
            "config": {
                key: {}
                for key in [
                    "application",
                    "challenges",
                    "ctf",
                    "hackingInstructor",
                    "memories",
                    "products",
                    "server",
                ]
            }
        }
    )
    assert native_identity(
        "/juice-shop/rest/admin/application-configuration",
        "GET",
        200,
        "application/json",
        config,
    )
    assert not native_identity(
        "/juice-shop/rest/admin/application-configuration",
        "GET",
        200,
        "application/json",
        '{"config":{}}',
    )
    assert not native_identity(
        "/juice-shop/rest/admin/application-configuration",
        "POST",
        200,
        "application/json",
        config,
    )
    assert native_identity(
        "/juice-shop/rest/admin/application-version",
        "GET",
        200,
        "application/json",
        '{"version":""}',
    )
    assert not native_identity(
        "/juice-shop/rest/admin/application-version",
        "GET",
        200,
        "application/json",
        '{"version":null}',
    )
    bundle = "application-configuration application-version juice-shop Juice Shop"
    assert native_identity(
        "/juice-shop/main.js", "GET", 200, "application/javascript", bundle
    )
    assert not native_identity("/juice-shop/main.js", "GET", 200, "text/html", bundle)
    assert not native_identity(
        "/juice-shop/main.js",
        "GET",
        200,
        "application/javascript",
        "console.log('generic')",
    )


def test_sensitive_ftp_denials_have_exact_discovery_contracts():
    scenario = next(
        r
        for r in json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
        if r["id"] == "juice-shop-exploits/07-sensitive-data"
    )
    requirements = scenario["dispatch_contract"]["requirements"]
    for filename in ("eastere.gg", "encrypt.pyc", "suspicious_errors.yml"):
        row = next(
            r for r in requirements if r.get("path") == "/juice-shop/ftp/" + filename
        )
        assert row["minimum_dispatches"] == 1
        contract = row["response_contract_by_status"]["403"]
        body = "<title>Error: Only .md and .pdf files are allowed!</title><h1>OWASP Juice Shop (Express ^4.22.1)</h1><h2><em>403</em> Error: Only .md and .pdf files are allowed!</h2>"
        assert response_content_matches(contract, "text/html", body)
        assert not response_content_matches(contract, "text/html", "Forbidden")
        assert not response_content_matches(contract, "application/json", body)
