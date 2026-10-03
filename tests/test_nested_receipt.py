"""Nested launch success cannot pass without child action verification."""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import traffic_runtime as runtime


def test_nested_exit_zero_without_dispatch_is_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("TARGET_FQDN", "www.example.test")
    scenario = {
        "id": "synthetic/action",
        "entrypoint": "scripts/traffic_dispatch.py",
        "kind": "shell",
        "budget": "http",
        "timeout_seconds": 1,
        "dispatch_contract": {
            "requirements": [
                {
                    "id": "action",
                    "method": "POST",
                    "path": "/httpbin/post",
                    "payload_class": "synthetic",
                    "minimum_dispatches": 1,
                }
            ]
        },
    }
    with patch.object(runtime, "execute", return_value={"outcome": "launched"}):
        assert runtime.run_nested(Path(__file__).resolve().parents[1], [scenario]) == 1
