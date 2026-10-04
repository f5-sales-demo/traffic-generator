"""Scoped synthetic role mutations require restoration of the original actor fields."""

import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module():
    spec = importlib.util.spec_from_file_location(
        "role_fixture", ROOT / "scripts/restaurant_profile_fixture.py"
    )
    assert spec is not None
    assert spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_role_fixture_restores_only_its_original_actor(tmp_path, monkeypatch):
    m = module()
    fixture = tmp_path / "fixtures.json"
    fixture.write_text(
        json.dumps(
            {
                "restaurant_attacker": {
                    "username": "tgen_bola_attacker",
                    "token": "synthetic",
                }
            }
        )
    )
    monkeypatch.setenv("TGEN_FIXTURES", str(fixture))
    monkeypatch.setenv("TGEN_RESULTS_DIR", str(tmp_path))
    profile = {
        "username": "tgen_bola_attacker",
        "phone_number": "2025550103",
        "first_name": "Example",
        "last_name": "Example",
        "role": "Customer",
    }
    with (
        patch.object(
            m.sys,
            "argv",
            ["fixture", "snapshot", "https://www.example.test/restaurant"],
        ),
        patch.object(m, "request", return_value=profile),
    ):
        assert m.main() == 0
    with (
        patch.object(
            m.sys, "argv", ["fixture", "restore", "https://www.example.test/restaurant"]
        ),
        patch.object(m, "request", side_effect=[{}, profile]) as request,
    ):
        assert m.main() == 0
        assert request.call_args_list[0].args[2]["role"] == "Customer"
    assert json.loads((tmp_path / "fixture-restoration.json").read_text())["restored"]
    bad = dict(profile, role="Chef")
    with (
        patch.object(
            m.sys, "argv", ["fixture", "restore", "https://www.example.test/restaurant"]
        ),
        patch.object(m, "request", side_effect=[{}, bad]),
        pytest.raises(ValueError, match="restoration"),
    ):
        m.main()


def test_role_fixture_rejects_foreign_target(monkeypatch):
    m = module()
    monkeypatch.setenv("TGEN_AUTHORIZED_DOMAINS", '["www.example.test"]')
    with pytest.raises(ValueError, match="unauthorized"):
        m.request("https://foreign.example/restaurant", "synthetic")
