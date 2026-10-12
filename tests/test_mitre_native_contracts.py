"""MITRE acceptance binds real tools, TLS routes, markers and exact native denials."""

import json
import re
from pathlib import Path

from traffic_dispatch import response_content_matches, verify_tool_actions
from traffic_native_identity import native_identity
from traffic_tool import attributed_arguments

ROOT = Path(__file__).parents[1]
CATALOG = {
    row["id"]: row
    for row in json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
}


def test_mitre_requires_actual_native_tools_and_complete_invocations():
    expected = {
        "01-reconnaissance": {"ffuf", "nikto", "whatweb"},
        "02-initial-access": {"hydra"},
        "04-credential-access": {"hydra", "medusa"},
        "05-discovery": set(),
        "06-collection-exfiltration": set(),
    }
    for name, tools in expected.items():
        contract = CATALOG["mitre-attack/" + name].get(
            "tool_contract", {"requirements": []}
        )
        assert {row["tool"] for row in contract["requirements"]} == tools
        if tools:
            events = [
                {
                    "tool": row["tool"],
                    "matched_requirements": [row["id"]],
                    "binary_sha256": "a" * 64,
                    "completed": True,
                    "exit_code": 0,
                }
                for row in contract["requirements"]
            ]
            assert verify_tool_actions(contract, events)["passed"]
            assert not verify_tool_actions(contract, events[:-1])["passed"]
            assert not verify_tool_actions(
                contract, [dict(row, exit_code=1) for row in events]
            )["passed"]


def test_native_hydra_and_medusa_keep_payloads_and_add_child_headers():
    original = [
        "-s",
        "443",
        "www.example.test",
        "https-post-form",
        r'/juice-shop/rest/user/login:{"email"\:"^USER^","password"\:"^PASS^"}:H=Content-Type\: application/json:F=Invalid',
    ]
    observed = attributed_arguments("hydra", original, "child-opaque")
    assert observed[:-1] == original[:-1]
    assert (
        observed[-1]
        == original[-1].removesuffix(":F=Invalid")
        + r":H=X-TGen-Child\: child-opaque:F=Invalid"
    )
    assert original[-1].endswith("application/json:F=Invalid")
    medusa = ["-M", "http", "-m", "DIR:/dvwa/login.php", "-n", "443", "-s"]
    assert attributed_arguments("medusa", medusa, "child-opaque") == [
        *medusa,
        "-m",
        "CUSTOM-HEADER:X-TGen-Child: child-opaque",
    ]
    for name in ("02-initial-access", "04-credential-access"):
        source = (ROOT / "suites/mitre-attack" / (name + ".sh")).read_text()
        assert "https-" in source
        assert "-s 80" not in source
        assert "-n 80" not in source
    assert (
        "USER-AGENT:Medusa/2.2"
        in (ROOT / "suites/mitre-attack/04-credential-access.sh").read_text()
    )


def test_exact_native_directory_denial_is_route_method_and_body_bound():
    scenario = CATALOG["mitre-attack/05-discovery"]
    for path in ("/dvwa/config/", "/dvwa/docs/"):
        requirement = next(
            row
            for row in scenario["dispatch_contract"]["requirements"]
            if row["path"] == path
        )
        contract = requirement["response_contract_by_status"]["403"]
        assert 403 in requirement["expected_statuses"]
        body = contract["text_exact"]
        assert response_content_matches(contract, "text/html", body)
        assert native_identity(path, "GET", 403, "text/html", body)
        assert not native_identity(path, "POST", 403, "text/html", body)
        assert not native_identity("/dvwa/unrelated/", "GET", 403, "text/html", body)
        assert not native_identity(path, "GET", 403, "text/html", "Forbidden")
        assert not response_content_matches(contract, "text/html", body + "unrelated")


def test_hydra_mitre_contract_matches_preserved_native_arguments():
    requirement = CATALOG["mitre-attack/02-initial-access"]["tool_contract"][
        "requirements"
    ][0]
    args = "-l admin -P /opt/seclists/Passwords/Common-Credentials/best15.txt -s 443 www.example.test https-get-form /dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:incorrect -t 4 -f -I"
    assert re.search(requirement["argument_regex"], args)
    assert not re.search(
        requirement["argument_regex"], args.replace("https-get-form", "http-get-form")
    )


def test_collection_native_file_denials_reuse_exact_qualified_contract():
    scenario = CATALOG["mitre-attack/06-collection-exfiltration"]
    for name in ("coupons_2013.md.bak", "package.json.bak", "eastere.gg"):
        requirement = next(
            row
            for row in scenario["dispatch_contract"]["requirements"]
            if row["path"] == "/juice-shop/ftp/" + name
        )
        assert 403 in requirement["expected_statuses"]
        contract = requirement["response_contract_by_status"]["403"]
        assert (
            "<h2><em>403</em> Error: Only .md and .pdf files are allowed!</h2>"
            in contract["text_contains"]
        )
        assert not response_content_matches(contract, "text/html", "Forbidden")


def test_impact_preserves_load_and_payloads_after_mitigated_login():
    scenario = CATALOG["mitre-attack/07-impact"]
    source = (ROOT / scenario["entrypoint"]).read_text()
    assert "-d15s --timeout 60s" in source
    assert "wrk-impact.log" in source
    assert scenario["native_report_contract"] == {"wrk": 1}
    assert scenario["fixture_refresh"] == ["juice"]
    assert "fixture_token.py" in source
    assert "admin" in source
    assert "--" in source
    feedback = next(
        row
        for row in scenario["dispatch_contract"]["requirements"]
        if row["id"] == "feedback"
    )
    assert 500 in feedback["expected_statuses"]
    assert (
        "captchaId"
        in feedback["response_contract_by_status"]["500"]["text_contains"][0]
    )
    assert not response_content_matches(
        feedback["response_contract_by_status"]["500"], "text/html", "Server Error"
    )


def test_idor_missing_native_address_route_is_exact_and_does_not_accept_other_500s():
    scenario = CATALOG["juice-shop-exploits/05-idor-basket-access"]
    row = next(
        row
        for row in scenario["dispatch_contract"]["requirements"]
        if row["id"] == "object-3"
    )
    contract = row["response_contract_by_status"]["500"]
    assert row["path"] == "/juice-shop/api/Addresses/1"
    assert contract["native_unexpected_path"]
    body = "".join(contract["text_contains"])
    assert response_content_matches(contract, "text/html", body)
    assert not response_content_matches(
        contract, "text/html", body.replace("/api/Addresses/1", "/api/Other/1")
    )
    assert not response_content_matches(contract, "text/html", "Server Error")


def test_native_security_and_swagger_discovery_keep_route_identity():
    body = "Contact: mailto:security@example.com\nEncryption: https://example.com/key.asc\nAcknowledgements: /#/score-board\nHiring: /#/jobs\nCsaf: http://localhost:3000/.well-known/csaf/provider-metadata.json\n"
    assert native_identity(
        "/juice-shop/.well-known/security.txt", "GET", 200, "text/plain", body
    )
    assert not native_identity(
        "/juice-shop/.well-known/security.txt",
        "GET",
        200,
        "text/plain",
        "Contact: unrelated",
    )
    swagger = "<title>Swagger UI</title> swagger-ui-bundle.js swagger-ui-init.js"
    assert native_identity(
        "/juice-shop/api-docs/swagger.json", "GET", 200, "text/html", swagger
    )
    assert not native_identity(
        "/juice-shop/api-docs/swagger.json", "GET", 200, "text/html", "Swagger"
    )
    scenario = CATALOG["juice-shop-exploits/07-sensitive-data"]
    paths = {row["path"] for row in scenario["dispatch_contract"]["requirements"]}
    assert "/juice-shop/ftp/coupons_2013.md.bak" in paths
    assert "/juice-shop/ftp/package.json.bak" in paths
