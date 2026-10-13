"""Supervised SQLMap must consume preserved request files and drain native reports."""

import json
import re
from pathlib import Path

from traffic_dispatch import match_requirements, verify_tool_actions


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
