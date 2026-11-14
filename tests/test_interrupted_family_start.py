"""Interrupted native family recovery is a declared startup prerequisite."""

import json
from pathlib import Path
from unittest.mock import patch

from traffic_family_fixture import recover_active


def test_active_journal_recovery_preserves_provenance(tmp_path):
    config = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "results_dir": str(tmp_path / "runtime"),
    }
    directory = Path(config["results_dir"]) / "pass-test" / "scenario"
    directory.mkdir(parents=True)
    journal = {
        "family": "vampi",
        "identity": "c" * 32,
        "source_commit": config["source_commit"],
        "artifact_sha256": config["artifact_sha256"],
    }
    (directory / "family-journal.json").write_text(json.dumps(journal))
    with patch("traffic_family_fixture.operation") as restore:
        receipt = recover_active(config)
    restore.assert_called_once_with(directory, "restore", "vampi")
    assert receipt["source_commit"] == config["source_commit"]
    assert receipt["artifact_sha256"] == config["artifact_sha256"]
    assert receipt["recovered"] == [
        {"family": "vampi", "identity": "c" * 32, "restored": True}
    ]
    assert (Path(config["results_dir"]) / "interrupted-family-recovery.json").is_file()


def test_service_declares_recovery_before_catalog_runtime():
    service = Path("scripts/tgen-continuous.service").read_text()
    assert service.index("traffic_family_fixture.py recover-active") < service.index(
        "ExecStart=/usr/bin/python3"
    )


def test_mixed_bundle_is_recovered_once(tmp_path):
    config = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "results_dir": str(tmp_path / "runtime"),
    }
    directory = Path(config["results_dir"]) / "pass-test" / "scenario"
    child = directory / "family-bundle" / "vampi"
    child.mkdir(parents=True)
    (directory / "family-bundle-identity.json").write_text(
        json.dumps({"identity": "c" * 32})
    )
    (child / "family-journal.json").write_text(
        json.dumps(
            {
                "source_commit": config["source_commit"],
                "artifact_sha256": config["artifact_sha256"],
            }
        )
    )
    with (
        patch("traffic_family_fixture.bundle_operation") as bundle,
        patch("traffic_family_fixture.operation") as single,
    ):
        result = recover_active(config)
    bundle.assert_called_once_with(directory, "restore")
    single.assert_not_called()
    assert result["recovered"][0]["family"] == "mixed"


def test_completed_and_failed_setup_journals_are_not_replayed(tmp_path):
    config = {
        "source_commit": "a" * 40,
        "artifact_sha256": "b" * 64,
        "results_dir": str(tmp_path / "runtime"),
    }
    root = Path(config["results_dir"]) / "pass-test"
    for name in ["complete", "failed", "foreign"]:
        d = root / name
        d.mkdir(parents=True)
        (d / "family-journal.json").write_text(
            json.dumps(
                {
                    "family": "vampi",
                    "identity": "c" * 32,
                    "source_commit": config["source_commit"]
                    if name != "foreign"
                    else "d" * 40,
                    "artifact_sha256": config["artifact_sha256"],
                }
            )
        )
    (root / "complete" / "family-restoration.json").write_text(
        json.dumps({"restored": True})
    )
    (root / "failed" / "receipt.json").write_text(
        json.dumps({"outcome": "fixture_failure"})
    )
    with patch("traffic_family_fixture.operation") as restore:
        result = recover_active(config)
    restore.assert_not_called()
    assert not result["recovered"]
