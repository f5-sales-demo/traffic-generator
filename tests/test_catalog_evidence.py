"""Evidence exchange rejects foreign paths, stale source and changed request bytes."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from catalog_evidence import install, pending


def fixture(tmp_path):
    source = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    (tmp_path / "source-receipt.json").write_text(json.dumps(source))
    directory = tmp_path / "runtime" / ("pass-" + "c" * 32) / "synthetic--action"
    directory.mkdir(parents=True)
    request = {**source, "scenario": "synthetic/action", "requests": []}
    file = directory / "control-evidence-request.json"
    file.write_text(json.dumps(request))
    bundle = {
        "pass": directory.parent.name,
        "request": request,
        "request_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
        "evidence": {**source, "checks": []},
    }
    return directory, bundle


def test_current_request_install_is_private_and_not_requeued(tmp_path):
    directory, bundle = fixture(tmp_path)
    assert len(pending(tmp_path)) == 1
    install(tmp_path, bundle)
    assert not pending(tmp_path)
    assert (directory / "control-attribution.json").stat().st_mode & 0o077 == 0


def test_changed_request_or_foreign_pass_never_writes(tmp_path):
    directory, bundle = fixture(tmp_path)
    bundle["pass"] = "../foreign"  # noqa: S105 - pass directory, not a password
    with pytest.raises(ValueError, match="invalid evidence"):
        install(tmp_path, bundle)
    bundle["pass"] = directory.parent.name
    bundle["request_sha256"] = "d" * 64
    with pytest.raises(ValueError, match="binding changed"):
        install(tmp_path, bundle)
    assert not (directory / "control-attribution.json").exists()


def test_stale_source_never_accept(tmp_path):
    _directory, bundle = fixture(tmp_path)
    (tmp_path / "source-receipt.json").write_text(
        json.dumps({"source_commit": "d" * 40, "artifact_sha256": "b" * 64})
    )
    assert not pending(tmp_path)
    with pytest.raises(ValueError, match="binding changed"):
        install(tmp_path, bundle)


def test_symlink_destination_never_accepts(tmp_path):
    directory, bundle = fixture(tmp_path)
    moved = directory.with_name("saved")
    directory.rename(moved)
    directory.symlink_to(moved)
    with pytest.raises(ValueError, match="symbolic link"):
        install(tmp_path, bundle)


def test_completed_pass_requests_do_not_delay_current_evidence(tmp_path):
    directory, bundle = fixture(tmp_path)
    (directory / "receipt.json").write_text(json.dumps({"functional_verified": False}))
    assert not pending(tmp_path)
    nested = directory / "nested" / "synthetic--child"
    nested.mkdir(parents=True)
    request = {**bundle["request"], "scenario": "synthetic/child"}
    (nested / "control-evidence-request.json").write_text(json.dumps(request))
    assert not pending(tmp_path)


def test_active_nested_evidence_round_trip_and_completed_ancestor_skip(tmp_path):
    directory, bundle = fixture(tmp_path)
    nested = directory / "nested-api" / "synthetic--child"
    nested.mkdir(parents=True)
    request = {**bundle["request"], "scenario": "synthetic/child"}
    file = nested / "control-evidence-request.json"
    file.write_text(json.dumps(request))
    requests = pending(tmp_path)
    child = next(
        item for item in requests if item["request"]["scenario"] == "synthetic/child"
    )
    assert child["directory"] == str(nested.relative_to(tmp_path / "runtime"))
    install(tmp_path, {**child, "evidence": bundle["evidence"]})
    assert (nested / "control-attribution.json").exists()
    (nested / "control-attribution.json").unlink()
    (directory / "receipt.json").write_text("{}")
    assert not pending(tmp_path)
