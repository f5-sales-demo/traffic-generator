"""Native load acceptance requires complete combinations, actual content and cleanup."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_functional import verify_load


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
