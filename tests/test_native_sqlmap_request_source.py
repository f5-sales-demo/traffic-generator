"""Supervised SQLMap must consume preserved request files and drain native reports."""

import html
import json
import re
from pathlib import Path

from traffic_dispatch import (
    match_requirements,
    response_content_matches,
    verify_responses,
    verify_tool_actions,
)
from traffic_native_identity import (
    juice_login_error_matches,
    juice_search_error_matches,
    juice_track_error_matches,
)


def test_all_five_sqlmap_scans_use_declared_targets_and_complete_reports():
    source = (
        Path(__file__).parents[1] / "suites/juice-shop-exploits/12-automated-sqlmap.sh"
    ).read_text()
    assert "--batch --ignore-stdin" in source
    assert source.count("${SQLMAP_CMD} ${SQLMAP_OPTS}") == 5
    assert source.count("--dbms=sqlite") == 5
    assert "| head -" not in source
    assert source.count("| sed -n") >= 5
    assert '-r "${TMPDIR}/login-request.txt"' in source
    assert '-r "${TMPDIR}/feedback-request.txt"' in source
    assert '-r "${TMPDIR}/register-request.txt"' in source

    assert '"username":"${MARKER}"' in source


def sqlmap_scenario():
    catalog = json.loads(
        (Path(__file__).parents[1] / "suites/catalog.json").read_text()
    )
    return next(
        row
        for row in catalog["scenarios"]
        if row["id"] == "juice-shop-exploits/12-automated-sqlmap"
    )


def test_five_distinct_native_sqlmap_invocations_are_required():
    assert sqlmap_scenario()["native_report_contract"] == {"sqlmap": 5}
    contract = sqlmap_scenario()["tool_contract"]
    invocations = [
        "--batch --ignore-stdin -u https://example.test/juice-shop/rest/products/search?q=test --skip-urlencode -p q --dbms=sqlite --dump-all",
        "--batch --ignore-stdin -r /tmp/owned/login-request.txt --dbms=sqlite --dump-all",
        "--batch --ignore-stdin -u https://example.test/juice-shop/rest/track-order/test* --dbms=sqlite --dump-all",
        "--batch --ignore-stdin -r /tmp/owned/feedback-request.txt --dbms=sqlite",
        "--batch --ignore-stdin -r /tmp/owned/register-request.txt --dbms=sqlite",
    ]
    assert len(contract["requirements"]) == 5
    events = []
    for arguments in invocations:
        matches = [
            requirement["id"]
            for requirement in contract["requirements"]
            if re.search(requirement["argument_regex"], arguments)
        ]
        assert len(matches) == 1
        events.append(
            {
                "tool": "sqlmap",
                "completed": True,
                "exit_code": 0,
                "binary_sha256": "a" * 64,
                "matched_requirements": matches,
            }
        )
    assert verify_tool_actions(contract, events)["passed"]
    for index in range(5):
        assert not verify_tool_actions(contract, events[:index] + events[index + 1 :])[
            "passed"
        ]
    assert not verify_tool_actions(contract, [events[0]] * 5)["passed"]


def test_native_sqlmap_path_injection_matches_path_and_rejects_query_substitution():
    contract = sqlmap_scenario()["dispatch_contract"]
    request = {
        "kind": "scenario",
        "method": "GET",
        "path": "/juice-shop/rest/track-order/test%27%2F%2A%2A%2FAND%2F%2A%2A%2F1%3D1",
        "query": "",
        "headers": {"user-agent": "synthetic-native-scanner"},
    }
    assert "scan-2" in match_requirements(contract, request)
    request["path"] = "/juice-shop/rest/track-order/test"
    request["query"] = "q=UNION"
    assert "scan-2" not in match_requirements(contract, request)
    request["path"] = "/unrelated/test%27AND"
    assert "scan-2" not in match_requirements(contract, request)


def test_native_sqlmap_reports_survive_temporary_request_cleanup():
    source = (
        Path(__file__).parents[1] / "suites/juice-shop-exploits/12-automated-sqlmap.sh"
    ).read_text()
    assert "${TGEN_RESULTS_DIR:?" in source
    assert "--output-dir=${REPORT_DIR}/sqlmap-output" in source
    for target in ("search", "login", "track", "feedback", "register"):
        assert 'tee "${REPORT_DIR}/sqlmap-' + target + '.log"' in source


def test_sqlmap_missing_captcha_error_is_exact_and_other_errors_fail():
    contract = sqlmap_scenario()["dispatch_contract"]
    request = {
        "kind": "scenario",
        "method": "POST",
        "path": "/juice-shop/api/Feedbacks/",
        "body": '{"comment":"test","rating":3}',
        "headers": {"user-agent": "native"},
    }
    matched = match_requirements(contract, request)
    assert "feedback-missing-captcha" in matched
    requirement = next(
        row
        for row in contract["requirements"]
        if row["id"] == "feedback-missing-captcha"
    )
    content = requirement["response_contract_by_status"]["500"]
    body = "".join(content["text_contains"])
    assert response_content_matches(content, "text/html", body)
    assert not response_content_matches(content, "text/html", "Internal Server Error")
    assert not response_content_matches(
        content, "text/html", body.replace("captchaId", "unrelated")
    )
    event = {
        "kind": "scenario",
        "status": 500,
        "matched_requirements": matched,
        "response_assertions": dict.fromkeys(matched, True),
    }
    assert verify_responses(
        {"requirements": [requirement], "reject_unmatched_errors": True}, [event]
    )["passed"]
    event["response_assertions"] = {}
    assert not verify_responses(
        {"requirements": [requirement], "reject_unmatched_errors": True}, [event]
    )["passed"]
    request["path"] = "/unrelated"
    assert "feedback-missing-captcha" not in match_requirements(contract, request)
    request["path"] = "/juice-shop/api/Feedbacks/"
    request["body"] = '{"comment":"test","rating":3,"captchaId":1}'
    assert "feedback-missing-captcha" not in match_requirements(contract, request)


def test_native_search_error_is_bound_to_requested_query_and_exact_error_frame():
    message = 'Error: SQLITE_ERROR: near "NativeProbe": syntax error'
    escaped = html.escape(message).replace("&#x27;", "&#39;")
    body = (
        "<title>" + escaped + "</title>"
        "<h1>OWASP Juice Shop (Express ^4.22.1)</h1>"
        "<h2><em>500</em> " + escaped + "</h2>"
    )
    path = "/juice-shop/rest/products/search"
    query = "q=test%27NativeProbe%3C%27%22%3Eprobe"
    assert juice_search_error_matches(path, "GET", query, "text/html", body)
    assert not juice_search_error_matches(path, "POST", query, "text/html", body)
    assert not juice_search_error_matches("/unrelated", "GET", query, "text/html", body)
    assert not juice_search_error_matches(
        path, "GET", "q=test%27OtherProbe", "text/html", body
    )
    assert not juice_search_error_matches(path, "GET", query, "application/json", body)
    assert not juice_search_error_matches(
        path, "GET", query, "text/html", body.replace("500", "503")
    )
    assert not juice_search_error_matches(
        path,
        "GET",
        query,
        "text/html",
        body.replace("syntax error", "database is locked"),
    )
    assert not juice_search_error_matches(
        path, "GET", query, "text/html", "Internal Server Error"
    )
    assert not juice_search_error_matches(path, "GET", "q=test", "text/html", body)


def test_sqlmap_search_dispatch_includes_preserved_literal_syntax_probe():
    scenario = sqlmap_scenario()
    request = {
        "kind": "scenario",
        "method": "GET",
        "path": "/juice-shop/rest/products/search",
        "query": "q=test'NativeProbe",
        "headers": {"user-agent": "native"},
    }
    assert "scan-0" in match_requirements(scenario["dispatch_contract"], request)
    requirement = next(
        row
        for row in scenario["dispatch_contract"]["requirements"]
        if row["id"] == "scan-0"
    )
    assert (
        requirement["response_contract_by_status"]["500"]["native_juice_search_error"]
        is True
    )
    request["query"] = "q=test"
    assert "scan-0" not in match_requirements(scenario["dispatch_contract"], request)


def test_native_track_syntax_error_rejects_published_route_failure():
    contract = sqlmap_scenario()["dispatch_contract"]
    row = next(row for row in contract["requirements"] if row["id"] == "scan-2")
    content = row["response_contract_by_status"]["500"]
    assert content["native_juice_track_error"] is True
    for suffix, message in (
        ("%27NativeProbe", "Unexpected identifier 'NativeProbe'"),
        ("%27)", "Unexpected token ')'"),
        ("%27", "Invalid or unexpected token"),
    ):
        path = "/juice-shop/rest/track-order/test" + suffix
        native = "SyntaxError: " + message
        body = (
            "<title>" + native + "</title>"
            "<h1>OWASP Juice Shop (Express ^4.22.1)</h1>"
            "<h2><em>500</em> " + native + "</h2>"
            "at Object.$where (/juice-shop/node_modules/marsdb/dist/DocumentMatcher.js:419:23)"
            "at /juice-shop/build/routes/trackOrder.js:50:29"
        )
        assert juice_track_error_matches(path, "GET", "text/html", body)
        assert not juice_track_error_matches(
            path, "GET", "text/html", body.replace("trackOrder.js", "otherRoute.js")
        )
        assert not juice_track_error_matches(path, "POST", "text/html", body)
        assert not juice_track_error_matches(
            path,
            "GET",
            "text/html",
            body.replace(native, "Error: Unexpected path: test"),
        )
        assert not juice_track_error_matches(
            "/juice-shop/rest/track-order/test", "GET", "text/html", body
        )
        assert not juice_track_error_matches(
            path, "GET", "text/html", "Internal Server Error"
        )
    event = {
        "kind": "scenario",
        "status": 500,
        "matched_requirements": ["scan-2"],
        "response_assertions": {"scan-2": True},
    }
    assert verify_responses({"requirements": [row]}, [event])["passed"]
    event["response_assertions"] = {"scan-2": False}
    assert not verify_responses({"requirements": [row]}, [event])["passed"]


def test_raw_sqlmap_requests_use_declared_https_transport():
    source = (
        Path(__file__).parents[1] / "suites/juice-shop-exploits/12-automated-sqlmap.sh"
    ).read_text()
    assert 'if [[ "${TARGET_PROTOCOL:-http}" == "https" ]]; then' in source
    assert 'SQLMAP_OPTS="${SQLMAP_OPTS} --force-ssl"' in source
    assert source.count("${SQLMAP_CMD} ${SQLMAP_OPTS}") == 5


def test_native_login_scan_continues_past_expected_unauthenticated_response():
    source = (
        Path(__file__).parents[1] / "suites/juice-shop-exploits/12-automated-sqlmap.sh"
    ).read_text()
    login = source.split('-r "${TMPDIR}/login-request.txt"', 1)[1].split("2>&1", 1)[0]
    assert "--ignore-code=401" in login
    assert source.count("--ignore-code=401") == 1
    assert "--ignore-code=403" not in source


def test_login_error_contract_rejects_generic_response_and_valid_request(monkeypatch):
    payload = b'{"email":"synthetic@example.com NativeProbe\'","password":"synthetic"}'
    path = "/juice-shop/rest/user/login"
    assert not juice_login_error_matches(path, "POST", payload, "text/html", "Error")

    # Isolate compile-only request qualification from the private pinned page bytes.
    class PinnedPageHash:
        def hexdigest(self):
            return "49eb674457de3379a1c5a7f845b7c1538d29e763645d3126145c918f3e19ebb7"

    monkeypatch.setattr(
        "traffic_native_identity.hashlib.sha256", lambda _: PinnedPageHash()
    )
    assert juice_login_error_matches(path, "POST", payload, "text/html", "pinned page")
    for request_path, method, data, media in (
        ("/other", "POST", payload, "text/html"),
        (path, "GET", payload, "text/html"),
        (path, "POST", payload, "application/json"),
        (path, "POST", b"invalid-json", "text/html"),
        (
            path,
            "POST",
            b'{"email":"valid@example.com","password":"synthetic"}',
            "text/html",
        ),
        (path, "POST", b'{"email":42,"password":"synthetic"}', "text/html"),
    ):
        assert not juice_login_error_matches(
            request_path, method, data, media, "pinned page"
        )


def test_sqlmap_login_500_requires_exact_native_request_bound_contract():
    contract = sqlmap_scenario()["dispatch_contract"]
    row = next(row for row in contract["requirements"] if row["id"] == "scan-1")
    assert row["response_contract_by_status"]["500"]["native_juice_login_error"]
    event = {
        "kind": "scenario",
        "status": 500,
        "matched_requirements": ["scan-1"],
        "response_assertions": {"scan-1": False},
    }
    assert not verify_responses({"requirements": [row]}, [event])["passed"]
