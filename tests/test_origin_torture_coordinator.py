"""Parent native load must restore before any child suite is dispatched."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import traffic_origin_torture


def test_parent_load_restores_before_children_and_keeps_failed_child_visible(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        ["coordinator", "cdn-load-testing/09-origin-torture", "api.example.test"],
    )
    order = []

    def load():
        order.append("load-restored")
        return 0

    def run(command, **kwargs):
        assert order[0] == "load-restored"
        order.append(command[-1])
        return SimpleNamespace(returncode=int(command[-1] == "dvga-exploits"))

    with (
        patch.object(traffic_origin_torture, "family_run", load),
        patch.object(traffic_origin_torture.subprocess, "run", run),
    ):
        assert traffic_origin_torture.main() == 1
    assert len(order) == 9
