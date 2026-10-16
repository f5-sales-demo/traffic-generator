"""Declared healthy pages must not pass startup with arbitrary method errors."""

import json
import sys
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import catalog_readiness
import pytest


def test_healthy_page_405_fails_readiness(tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"domains": ["www.example.test", "api.example.test"]}))
    page = {"content_type": "text/html", "identity": "Expected app"}
    with (
        patch.object(sys, "argv", ["readiness", "--config", str(config)]),
        patch.object(catalog_readiness, "validate_config"),
        patch.object(catalog_readiness, "hydra_verified", return_value=True),
        patch.object(catalog_readiness, "wrk_verified", return_value=True),
        patch.object(
            catalog_readiness, "load_catalog", return_value={"required_assets": []}
        ),
        patch.object(catalog_readiness, "readiness", return_value={"ready": True}),
        patch.object(
            catalog_readiness,
            "application_readiness_paths",
            return_value={"/fixture/": page},
        ),
        patch.object(catalog_readiness.subprocess, "run") as run,
        patch.object(
            catalog_readiness,
            "urlopen",
            side_effect=HTTPError(
                "https://www.example.test/fixture/", 405, "method", Message(), None
            ),
        ),
    ):
        run.return_value.returncode = 0
        assert catalog_readiness.main() == 1
    receipt = json.loads(capsys.readouterr().out)
    assert not receipt["ready"]
    assert all(not route["ready"] for route in receipt["routes"])


@pytest.mark.parametrize(
    ("hydra", "wrk", "exit_code"), [(True, True, 0), (False, True, 1), (True, False, 1)]
)
def test_native_artifact_drift_fails_otherwise_ready_start(
    tmp_path, capsys, hydra, wrk, exit_code
):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"domains": ["www.example.test"]}))
    with (
        patch.object(sys, "argv", ["readiness", "--config", str(config)]),
        patch.object(catalog_readiness, "validate_config"),
        patch.object(
            catalog_readiness, "load_catalog", return_value={"required_assets": []}
        ),
        patch.object(catalog_readiness, "readiness", return_value={"ready": True}),
        patch.object(catalog_readiness, "hydra_verified", return_value=hydra),
        patch.object(catalog_readiness, "wrk_verified", return_value=wrk),
        patch.object(catalog_readiness, "application_readiness_paths", return_value={}),
        patch.object(catalog_readiness.subprocess, "run") as run,
    ):
        run.return_value.returncode = 0
        assert catalog_readiness.main() == exit_code
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["native_hydra_verified"] is hydra
    assert receipt["native_wrk_verified"] is wrk
    assert receipt["ready"] is (exit_code == 0)
