"""Native family recovery cannot pass with missing replicas or stale provenance."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from unittest.mock import patch

from traffic_family_fixture import bundle_operation
from traffic_family_functional import family_restored
from traffic_native_identity import native_identity
from traffic_network import NetworkBoundary


def test_family_recovery_requires_exact_four_replica_baselines(tmp_path):
    result = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    replicas: dict = {
        "vampi-" + str(i): {"users": [], "books": []} for i in range(1, 5)
    }
    before = {**result, "identity": "c" * 32, "replicas": replicas}
    after = {**before, "restored": True, "after": replicas}
    (tmp_path / "family-baseline.json").write_text(json.dumps(before))
    path = tmp_path / "family-restoration.json"
    path.write_text(json.dumps(after))
    assert family_restored(result, tmp_path)
    after["after"] = {"vampi-1": replicas["vampi-1"]}
    path.write_text(json.dumps(after))
    assert not family_restored(result, tmp_path)
    after["after"] = replicas
    after["source_commit"] = "d" * 40
    path.write_text(json.dumps(after))
    assert not family_restored(result, tmp_path)


def test_dvwa_recovery_requires_marker_bound_four_replica_receipt(tmp_path):
    result = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    replicas: dict = {
        "dvwa-" + str(i): {"guestbook": [], "uploads": {}} for i in range(1, 5)
    }
    before = {
        **result,
        "identity": "c" * 32,
        "family": "dvwa",
        "marker": "tgen-" + "c" * 32,
        "replicas": replicas,
    }
    after = {**before, "restored": True, "after": replicas}
    (tmp_path / "family-baseline.json").write_text(json.dumps(before))
    file = tmp_path / "family-restoration.json"
    file.write_text(json.dumps(after))
    assert family_restored(result, tmp_path)
    after["marker"] = "tgen-" + "d" * 32
    file.write_text(json.dumps(after))
    assert not family_restored(result, tmp_path)


def test_owned_upload_readback_rejects_wrong_native_content():
    path = "/dvwa/hackable/uploads/tgen-" + "a" * 32 + "-shell.php"
    assert native_identity(
        path, "GET", 200, "text/html", "UPLOAD_SUCCESSuid=33(www-data)"
    )
    assert not native_identity(path, "GET", 200, "text/html", "DVWA login form")
    assert not native_identity(
        path.replace("shell.php", "foreign.php"),
        "GET",
        200,
        "text/html",
        "UPLOAD_SUCCESSuid=33(www-data)",
    )


def test_mixed_family_restoration_requires_all_twenty_replica_baselines(tmp_path):
    result = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    replicas: dict = {
        family + "-" + str(i): {}
        for family in ["vampi", "dvwa", "restaurant", "juice-shop", "dvga"]
        for i in range(1, 5)
    }
    before = {
        **result,
        "identity": "c" * 32,
        "family": "mixed",
        "marker": "tgen-" + "c" * 32,
        "replicas": replicas,
    }
    (tmp_path / "family-baseline.json").write_text(json.dumps(before))
    file = tmp_path / "family-restoration.json"
    file.write_text(json.dumps({**before, "restored": True, "after": replicas}))
    assert family_restored(result, tmp_path)
    replicas.pop("dvga-4")
    file.write_text(json.dumps({**before, "restored": True, "after": replicas}))
    assert not family_restored(result, tmp_path)


def test_partial_bundle_snapshot_restores_prepared_families(tmp_path, monkeypatch):
    calls = []

    def operation(directory, action, family, identity=None):
        calls.append((action, family))
        if action == "prepare" and family == "restaurant":
            message = "native snapshot failed"
            raise ValueError(message)
        file = directory / (
            "family-baseline.json" if action == "prepare" else "family-restoration.json"
        )
        file.write_text(
            json.dumps(
                {
                    "identity": identity,
                    "marker": "tgen-" + identity,
                    "replicas": {},
                    "after": {},
                    "restored": action == "restore",
                }
            )
        )

    monkeypatch.setenv("SOURCE_COMMIT", "a" * 40)
    monkeypatch.setenv("TGEN_ARTIFACT_SHA256", "b" * 64)
    monkeypatch.setattr("traffic_family_fixture.operation", operation)
    with pytest.raises(ValueError, match="native snapshot"):
        bundle_operation(tmp_path, "prepare")
    assert ("restore", "vampi") in calls
    assert ("restore", "dvwa") in calls


def test_host_recovery_never_executes_without_owned_journal(tmp_path):
    boundary = object.__new__(NetworkBoundary)
    boundary.root = tmp_path
    boundary.runtime = tmp_path / "runtime"
    boundary.config = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    with patch("traffic_network.subprocess.run") as run:
        assert not boundary.recover_family(tmp_path, "vampi")
        run.assert_not_called()
