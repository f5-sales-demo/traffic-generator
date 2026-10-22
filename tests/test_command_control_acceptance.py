"""Native commands require output or an exact request-bound protection receipt."""

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from traffic_functional import verify_commands


def test_command_block_needs_matching_response_hash_and_control(tmp_path):
    digest = hashlib.sha256(b"owned blocking response").hexdigest()
    scenario = {
        "id": "dvwa-exploits/02-command-injection",
        "dispatch_contract": {"requirements": [{"id": "command-0"}]},
        "functional_contract": {"behavior": "native command output or exact control"},
    }
    row = {
        "status": 403,
        "response_sha256": digest,
        "passed": False,
        "mitigation_candidate": True,
        "synthetic_identity": "showcase-command-request",
    }
    (tmp_path / "command-functional.jsonl").write_text(json.dumps(row) + "\n")
    result = {
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    response = {
        "scenario": scenario["id"],
        "kind": "scenario",
        "method": "POST",
        "path": "/dvwa/vulnerabilities/exec/",
        "status": 403,
        "response_sha256": digest,
        "matched_requirements": ["command-0"],
        "control_attributed": True,
        "synthetic_identity": "showcase-command-request",
    }
    with patch(
        "traffic_command_functional.attributed_responses", return_value=[response]
    ):
        assert verify_commands(scenario, result, tmp_path)["passed"]
    response["control_attributed"] = False
    with patch(
        "traffic_command_functional.attributed_responses", return_value=[response]
    ):
        assert not verify_commands(scenario, result, tmp_path)["passed"]
    response["control_attributed"] = True
    response["response_sha256"] = "f" * 64
    with patch(
        "traffic_command_functional.attributed_responses", return_value=[response]
    ):
        assert not verify_commands(scenario, result, tmp_path)["passed"]


def test_sqlmap_uses_only_supported_native_options():
    source = (
        Path(__file__).parents[1] / "suites/juice-shop-exploits/12-automated-sqlmap.sh"
    ).read_text()
    assert "--stop-at-first-success" not in source
    assert source.count("${SQLMAP_CMD} ${SQLMAP_OPTS}") == 5
