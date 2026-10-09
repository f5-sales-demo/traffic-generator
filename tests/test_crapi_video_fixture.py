"""Video fixtures require exact media/actor restoration and reject blocked setup."""

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import crapi_video_fixture as fixture
from traffic_functional import verify_video_conversion, verify_video_deletion
from traffic_runtime import video_fixture_verification


def test_video_restore_preserves_media_name_and_conversion_parameters():
    before = {
        "id": 8,
        "video_name": "synthetic.mp4",
        "conversion_params": "-v codec h264",
        "profileVideo": "data:image/jpeg;base64,Zml4dHVyZQ==",
    }
    with patch.object(
        fixture, "request", side_effect=[{"id": 8}, {}, before]
    ) as request:
        assert fixture.recover("https://www.example.test/crapi", "synthetic", before)[
            "restored"
        ]
        assert b"fixture" in request.call_args_list[0].args[3]
        assert b"synthetic.mp4" in request.call_args_list[1].args[3]
    changed = dict(before, conversion_params="mutated")
    with patch.object(fixture, "request", side_effect=[{"id": 8}, {}, changed]):
        assert not fixture.recover(
            "https://www.example.test/crapi", "synthetic", before
        )["restored"]
    with (
        patch.object(fixture, "request", return_value={"id": 9}),
        pytest.raises(ValueError, match="actor"),
    ):
        fixture.recover("https://www.example.test/crapi", "synthetic", before)


def test_missing_media_and_foreign_route_fail(monkeypatch):
    with pytest.raises(ValueError, match="bytes"):
        fixture.video_bytes({})
    monkeypatch.setenv("TGEN_AUTHORIZED_DOMAINS", '["www.example.test"]')
    with pytest.raises(ValueError, match="unauthorized"):
        fixture.request(
            "https://foreign.example/crapi",
            "/identity/api/v2/user/videos/8",
            "synthetic",
        )


def test_missing_video_restoration_receipt_cannot_pass(tmp_path):
    result = {"outcome": "launched", "dispatch_contract_verified": True}
    video_fixture_verification(
        tmp_path, {"fixture_contract": {"restore_video": True}}, result
    )
    assert result["outcome"] == "fixture_failure"
    assert not result["dispatch_contract_verified"]


def test_disposable_delete_requires_every_owned_upload_and_native_absence(tmp_path):
    scenario = {"functional_contract": {"behavior": "native owned deletion"}}
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "disposable_video_cleanup": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    rows = [
        {
            "attempt": i,
            "video_id": i + 1,
            "upload_status": 200,
            "delete_status": 200,
            "absent_status": 404,
        }
        for i in range(1, 5)
    ]
    evidence: dict = {
        "source_commit": result["source_commit"],
        "artifact_sha256": result["artifact_sha256"],
        "removed": True,
        "owned_uploads": 4,
        "objects": rows,
    }
    p = tmp_path / "video-deletion-cleanup.json"
    p.write_text(json.dumps(evidence))
    assert verify_video_deletion(scenario, result, tmp_path)["passed"]
    rows[-1]["absent_status"] = 200
    p.write_text(json.dumps(evidence))
    assert not verify_video_deletion(scenario, result, tmp_path)["passed"]


def test_video_restore_receipt_binds_media_and_metadata_readback():
    before = {
        "id": 8,
        "video_name": "synthetic.mp4",
        "conversion_params": "-v codec h264",
        "profileVideo": "data:image/jpeg;base64,Zml4dHVyZQ==",
    }
    with patch.object(fixture, "request", side_effect=[{"id": 8}, {}, before]):
        receipt = fixture.recover("https://www.example.test/crapi", "synthetic", before)
    assert receipt["before"] == receipt["after"]
    assert receipt["before"]["media_sha256"]


def test_conversion_functional_requires_all_native_triggers_and_exact_recovery(
    tmp_path,
):
    before = {
        "id": 8,
        "video_name": "synthetic.mp4",
        "conversion_params": "-v codec h264",
        "profileVideo": "data:image/jpeg;base64,Zml4dHVyZQ==",
    }
    (tmp_path / "crapi-video-snapshot.json").write_text(json.dumps(before))
    identity = {k: before[k] for k in ["id", "video_name", "conversion_params"]}
    identity["media_sha256"] = hashlib.sha256(b"fixture").hexdigest()
    recovery = {
        "before": identity,
        "after": identity,
        "restored": True,
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
    }
    (tmp_path / "video-restoration.json").write_text(json.dumps(recovery))
    scenario = {
        "functional_contract": {"behavior": "native conversion"},
        "dispatch_contract": {
            "requirements": [
                {"id": "trigger", "minimum_dispatches": 3, "expected_statuses": [200]}
            ]
        },
    }
    result = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "video_restoration": True,
        "outcome": "launched",
        "dispatch_contract_verified": True,
        "transport_failures": 0,
        "tool_cancellations": 0,
    }
    rows = [
        {
            "kind": "scenario",
            "matched_requirements": ["trigger"],
            "upstream_dispatched": True,
            "status": 200,
            "response_assertions": {"trigger": True},
        }
        for _ in range(3)
    ]
    assert verify_video_conversion(scenario, result, rows, tmp_path)["passed"]
    rows.pop()
    assert not verify_video_conversion(scenario, result, rows, tmp_path)["passed"]
