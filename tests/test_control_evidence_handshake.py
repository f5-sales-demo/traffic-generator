"""Only source-bound real blocked responses can request or satisfy operator evidence."""

import json
import sys
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_security import await_control_evidence


def test_handshake_persists_actual_request_and_never_credentials(tmp_path):
    row = {
        "scenario": "synthetic/action",
        "kind": "scenario",
        "status": 403,
        "upstream_dispatched": True,
        "outcome": "mitigation_candidate",
        "synthetic_identity": "showcase-synthetic",
        "payload_sha256": "a" * 64,
    }
    (tmp_path / "response-events.jsonl").write_text(json.dumps(row) + "\n")
    scenario = {
        "id": "synthetic/action",
        "functional_contract": {"waf_signatures": ["200000098"]},
    }
    result = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    with patch("traffic_security.waf_attribution", return_value=True):
        await_control_evidence(scenario, result, tmp_path, threading.Event())
    receipt = json.loads((tmp_path / "control-evidence-request.json").read_text())
    assert receipt["requests"] == [row]
    assert receipt["source_commit"] == result["source_commit"]
    assert (tmp_path / "control-evidence-request.json").stat().st_mode & 0o077 == 0


def test_handshake_skips_native_rejection_and_unconfigured_signature(tmp_path):
    row = {
        "scenario": "synthetic/action",
        "kind": "scenario",
        "status": 403,
        "upstream_dispatched": True,
        "outcome": "expected_application_rejection",
    }
    (tmp_path / "response-events.jsonl").write_text(json.dumps(row) + "\n")
    await_control_evidence(
        {
            "id": "synthetic/action",
            "functional_contract": {"waf_signatures": ["200000098"]},
        },
        {},
        tmp_path,
        threading.Event(),
    )
    assert not (tmp_path / "control-evidence-request.json").exists()
