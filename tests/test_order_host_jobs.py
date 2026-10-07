"""Nested order jobs remain source-bound and restricted to declared recovery actions."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_order_host import host_jobs


class OnePoll:
    def __init__(self):
        self.calls = 0

    def wait(self, _seconds):
        self.calls += 1
        return self.calls > 1


def test_source_bound_host_job_uses_fixed_helper_and_private_result(tmp_path):
    runtime = tmp_path / "runtime"
    directory = runtime / ("pass-" + "a" * 32) / "parent" / "nested-child" / "scenario"
    directory.mkdir(parents=True)
    config = {"source_commit": "b" * 40, "artifact_sha256": "c" * 64}
    job = {**config, "action": "restore", "identity": "d" * 32}
    (directory / "order-host-request.json").write_text(json.dumps(job))
    with patch(
        "traffic_order_host.subprocess.run", return_value=SimpleNamespace(returncode=0)
    ) as run:
        host_jobs(tmp_path, runtime, config, OnePoll())
    assert run.call_args.args[0][-2:] == ["restore", str(directory)]
    assert run.call_args.kwargs["env"]["SOURCE_COMMIT"] == config["source_commit"]
    receipt = directory / "order-host-response.json"
    assert json.loads(receipt.read_text())["request"] == job
    assert receipt.stat().st_mode & 0o077 == 0


def test_stale_source_and_arbitrary_action_do_not_execute(tmp_path):
    runtime = tmp_path / "runtime"
    directory = runtime / "pass-test" / "scenario"
    directory.mkdir(parents=True)
    config = {"source_commit": "b" * 40, "artifact_sha256": "c" * 64}
    (directory / "order-host-request.json").write_text(
        json.dumps({**config, "action": "shell", "source_commit": "d" * 40})
    )
    with patch("traffic_order_host.subprocess.run") as run:
        host_jobs(tmp_path, runtime, config, OnePoll())
    run.assert_not_called()
    assert (
        json.loads((directory / "order-host-response.json").read_text())["passed"]
        is False
    )
