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
