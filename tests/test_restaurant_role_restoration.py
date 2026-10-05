"""Scoped synthetic role mutations require restoration of the original actor fields."""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_functional import verify_role_mutation  # noqa: E402 - owned scripts path


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


def test_role_restore_receipt_contains_native_before_after_and_source(
    tmp_path, monkeypatch
):
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
    monkeypatch.setenv("SOURCE_COMMIT", "a" * 40)
    monkeypatch.setenv("TGEN_ARTIFACT_SHA256", "b" * 64)
    profile = dict.fromkeys(m.FIELDS, "synthetic")
    profile["username"] = "tgen_bola_attacker"
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
        patch.object(m, "request", side_effect=[{}, profile]),
    ):
        assert m.main() == 0
    receipt = json.loads((tmp_path / "fixture-restoration.json").read_text())
    assert receipt["before"] == receipt["after"] == profile
    assert receipt["source_commit"] == "a" * 40
    assert receipt["artifact_sha256"] == "b" * 64


def test_role_mutation_rejects_missing_payload_or_failed_restoration(tmp_path):

    before = {"username": "tgen_bola_attacker", "role": "Customer"}
    (tmp_path / "restaurant-role-snapshot.json").write_text(json.dumps(before))
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "fixture_restoration": True,
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    rows = [
        {
            "id": "role-" + str(i),
            "profile": dict(before, role=role),
            "source_commit": result["source_commit"],
            "artifact_sha256": result["artifact_sha256"],
        }
        for i, role in enumerate(["Chef"] * 6)
    ]
    r = {
        "before": before,
        "after": before,
        "restored": True,
        "source_commit": result["source_commit"],
        "artifact_sha256": result["artifact_sha256"],
    }
    (tmp_path / "fixture-restoration.json").write_text(json.dumps(r))
    p = tmp_path / "role-native-outcomes.jsonl"
    p.write_text("\n".join(json.dumps(row) for row in rows))
    s = {"functional_contract": {"behavior": "native role changes"}}
    assert verify_role_mutation(s, result, tmp_path)["passed"]
    p.write_text("\n".join(json.dumps(row) for row in rows[:-1]))
    assert not verify_role_mutation(s, result, tmp_path)["passed"]
