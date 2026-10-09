"""Nested work inherits every declared limit and isolates identity and tool wrappers."""

import json
import os
from pathlib import Path
from unittest.mock import patch

from traffic_inherited import InheritedBoundary


def test_child_uses_its_declared_duration_and_new_identity(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (tmp_path / "fixtures.json").write_text("{}")
    values = {
        "TGEN_RUNTIME_DIR": str(runtime),
        "TMPDIR": str(tmp_path),
        "TGEN_AUTHORIZED_DOMAINS": json.dumps(["www.example.test", "api.example.test"]),
        "TGEN_CONNECTION_RATE": "20",
        "TGEN_SLOW_CONNECTIONS": "20",
        "SOURCE_COMMIT": "a" * 40,
        "TGEN_ARTIFACT_SHA256": "b" * 64,
        "RUN_ID": "parent-run",
        "TGEN_DURATION": "600",
        "TGEN_ATTACK_RATE": "1",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    boundary = InheritedBoundary.inherited(Path(__file__).parents[1])
    child = tmp_path / "child"
    child.mkdir()
    scenario = {
        "id": "dvga-exploits/01-batch-query-dos",
        "suite": "dvga-exploits",
        "duration_seconds": 15,
        "tool_contract": {"requirements": [{"tool": "curl"}]},
    }
    with patch("traffic_network.native_binary", return_value="/usr/bin/curl"):
        environment = boundary.environment(scenario, "www.example.test", child)
    assert environment["TGEN_DURATION"] == "15"
    assert environment["TGEN_ATTACK_RATE"] == "20"
    assert environment["TGEN_REQUEST_TIMEOUT"] == "600"
    assert environment["RUN_ID"] != "parent-run"
    assert environment["TGEN_RESULTS_DIR"] == str(child)
    assert (child / "tool-bin/curl").is_file()
    assert environment["PATH"].startswith(str(child / "tool-bin") + os.pathsep)
    assert boundary.wrap(["curl", "https://www.example.test"]) == [
        "curl",
        "https://www.example.test",
    ]
