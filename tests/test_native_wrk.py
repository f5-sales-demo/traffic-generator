"""Native load source verification fails before promotion of corrupted artifacts."""

import hashlib
import io
import json
from pathlib import Path
from unittest.mock import patch

import install_native_wrk as native
import pytest
from install_native_wrk import install
from wrk_drain_adapter import replace_once


def test_corrupted_native_archive_preserves_existing_binary(tmp_path):
    binary = tmp_path / "bin/wrk"
    binary.parent.mkdir()
    binary.write_bytes(b"existing")
    with (
        patch("install_native_wrk.urlopen", return_value=io.BytesIO(b"corrupt")),
        pytest.raises(ValueError, match="digest mismatch"),
    ):
        install(tmp_path)
    assert binary.read_bytes() == b"existing"


def test_pinned_adapter_rejects_missing_and_ambiguous_anchors():
    assert replace_once("native anchor", "anchor", "patched") == "native patched"
    for source in ("missing", "anchor anchor"):
        with pytest.raises(ValueError, match="anchor mismatch"):
            replace_once(source, "anchor", "patched")


def test_verified_binary_and_adapter_receipt_make_reinstall_idempotent(tmp_path):
    binary = tmp_path / "bin/wrk"
    binary.parent.mkdir()
    binary.write_bytes(b"verified")
    receipt = {
        "source_commit": native.COMMIT,
        "archive_sha256": native.ARCHIVE_SHA256,
        "adapter_sha256": hashlib.sha256(
            Path(native.__file__).with_name("wrk_drain_adapter.py").read_bytes()
        ).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    (tmp_path / "native-wrk-receipt.json").write_text(json.dumps(receipt))
    with patch("install_native_wrk.urlopen") as fetch:
        assert install(tmp_path) == receipt
    fetch.assert_not_called()
