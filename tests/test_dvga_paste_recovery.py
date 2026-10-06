"""Recovery verifies owned state after success, ambiguous writes and interruption."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from dvga_paste_acceptance import verify_pastes
from dvga_paste_fixture import CONTENT, PAYLOADS, Pastes, graphql, request


def fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_COMMIT", "a" * 40)
    monkeypatch.setenv("TGEN_ARTIFACT_SHA256", "b" * 64)
    monkeypatch.setenv("TGEN_AUTHORIZED_DOMAINS", '["example.com"]')
    return Pastes("https://example.com/dvga", tmp_path)


def owned(pastes, index=0):
    title = "tgen-paste-" + pastes.journal["identity"] + "-" + str(index)
    item = {"index": index, "title": title, "id": None}
    pastes.journal["objects"].append(item)
    pastes.persist()
    return {"id": "7", "title": title, "content": CONTENT + "|" + PAYLOADS[index]}


def test_ambiguous_write_recovery_and_repeated_absence(tmp_path, monkeypatch):
    pastes = fixture(tmp_path, monkeypatch)
    native = owned(pastes)
    with patch(
        "dvga_paste_fixture.graphql",
        side_effect=[
            {"paste": native},
            {"paste": native},
            {"deletePaste": {"result": True}},
            {"paste": None},
            {"paste": None},
        ],
    ) as api:
        assert pastes.recover()["restored"]
        assert api.call_count == 5
    resumed = Pastes(pastes.base, tmp_path, resume=True)
    with patch(
        "dvga_paste_fixture.graphql", side_effect=[{"paste": None}, {"paste": None}]
    ):
        assert resumed.recover()["restored"]
    assert (tmp_path / "paste-journal.json").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("change", ["title", "content", "id"])
def test_ownership_change_prevents_deletion(tmp_path, monkeypatch, change):
    pastes = fixture(tmp_path, monkeypatch)
    native = owned(pastes)
    if change == "id":
        pastes.journal["objects"][0]["id"] = "8"
    else:
        native[change] = "unrelated"
    with (
        patch("dvga_paste_fixture.graphql", return_value={"paste": native}) as api,
        pytest.raises(ValueError, match="ownership"),
    ):
        pastes.recover()
    assert api.call_count == 1
    assert not (tmp_path / "paste-restoration.json").exists()


@pytest.mark.parametrize("documents", [[{}, {"paste": None}], [{"paste": None}, {}]])
def test_absent_field_is_not_null_proof(tmp_path, monkeypatch, documents):
    pastes = fixture(tmp_path, monkeypatch)
    owned(pastes)
    with (
        patch("dvga_paste_fixture.graphql", side_effect=documents),
        pytest.raises(ValueError, match="missing"),
    ):
        pastes.recover()


def test_delete_failure_cannot_write_restoration_receipt(tmp_path, monkeypatch):
    pastes = fixture(tmp_path, monkeypatch)
    native = owned(pastes)
    with (
        patch(
            "dvga_paste_fixture.graphql",
            side_effect=[
                {"paste": native},
                {"paste": native},
                {"deletePaste": {"result": False}},
            ],
        ),
        pytest.raises(ValueError, match="removal"),
    ):
        pastes.recover()
    assert not (tmp_path / "paste-restoration.json").exists()


def test_transport_timeout_preserves_prewrite_journal(tmp_path, monkeypatch):
    pastes = fixture(tmp_path, monkeypatch)
    with (
        patch("dvga_paste_fixture.request", side_effect=TimeoutError),
        pytest.raises(TimeoutError),
    ):
        pastes.execute()
    resumed = Pastes(pastes.base, tmp_path, resume=True)
    assert len(resumed.journal["objects"]) == 1
    assert resumed.journal["objects"][0]["id"] is None
    with patch(
        "dvga_paste_fixture.graphql", side_effect=[{"paste": None}, {"paste": None}]
    ):
        assert resumed.recover()["restored"]


def test_foreign_target_and_error_document_rejected(tmp_path, monkeypatch):
    fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="unauthorized"):
        request("https://foreign.invalid/dvga", "{pastes{id}}")
    with (
        patch(
            "dvga_paste_fixture.request",
            return_value=(200, {"errors": [{"message": "failure"}]}),
        ),
        pytest.raises(ValueError, match="missing"),
    ):
        graphql("https://example.com/dvga", "{pastes{id}}")


def test_complete_native_evidence_and_missing_or_stale_receipt(tmp_path, monkeypatch):
    pastes = fixture(tmp_path, monkeypatch)
    responses = []
    recovery = []
    for i in range(len(PAYLOADS)):
        native = owned(pastes, i)
        pastes.journal["objects"][i]["id"] = native["id"]
        pastes.journal["attempts"].append(
            {"index": i, "status": 200, "stored": True, "readback": native}
        )
        responses.append(
            {
                "kind": "scenario",
                "matched_requirements": ["xss-" + str(i)],
                "upstream_dispatched": True,
                "status": 200,
            }
        )
        recovery.append(
            {"index": i, "title": native["title"], "after": None, "removed": True}
        )
    pastes.persist()
    receipt = {
        **{
            k: pastes.journal[k]
            for k in ("identity", "source_commit", "artifact_sha256")
        },
        "objects": recovery,
        "restored": True,
    }
    path = tmp_path / "paste-restoration.json"
    path.write_text(json.dumps(receipt))
    events = tmp_path / "response-events.jsonl"
    events.write_text("\n".join(json.dumps(r) for r in responses))
    scenario = {"functional_contract": {"behavior": "native stored paste"}}
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "paste_restoration": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    assert verify_pastes(scenario, result, tmp_path)["passed"]
    events.write_text("\n".join(json.dumps(r) for r in responses[:-1]))
    assert not verify_pastes(scenario, result, tmp_path)["passed"]
    events.write_text("\n".join(json.dumps(r) for r in responses))
    receipt["source_commit"] = "c" * 40
    path.write_text(json.dumps(receipt))
    assert not verify_pastes(scenario, result, tmp_path)["passed"]
    path.write_text("{}")
    assert not verify_pastes(scenario, result, tmp_path)["passed"]
