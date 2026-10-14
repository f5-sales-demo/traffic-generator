"""Native load source verification fails before promotion of corrupted artifacts."""

import hashlib
import io
import json
from pathlib import Path
from unittest.mock import patch

import install_native_hydra as native
import pytest
from install_native_hydra import install


def test_corrupted_native_archive_preserves_existing_binary(tmp_path):
    binary = tmp_path / "bin/hydra"
    binary.parent.mkdir()
    binary.write_bytes(b"existing")
    with (
        patch("install_native_hydra.urlopen", return_value=io.BytesIO(b"corrupt")),
        pytest.raises(ValueError, match="digest mismatch"),
    ):
        install(tmp_path)
    assert binary.read_bytes() == b"existing"


def test_verified_binary_and_installer_receipt_make_reinstall_idempotent(tmp_path):
    binary = tmp_path / "bin/hydra"
    binary.parent.mkdir()
    binary.write_bytes(b"verified")
    binary.chmod(0o755)
    receipt = {
        "source_commit": native.COMMIT,
        "archive_sha256": native.ARCHIVE_SHA256,
        "installer_sha256": hashlib.sha256(
            Path(native.__file__).read_bytes()
        ).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    (tmp_path / "native-hydra-receipt.json").write_text(json.dumps(receipt))
    with patch("install_native_hydra.urlopen") as fetch:
        assert install(tmp_path) == receipt
    fetch.assert_not_called()


def test_runtime_readback_rejects_binary_drift_and_wrong_owner(tmp_path):
    binary = tmp_path / "bin/hydra"
    binary.parent.mkdir()
    binary.write_bytes(b"verified")
    binary.chmod(0o755)
    receipt = {
        "source_commit": native.COMMIT,
        "archive_sha256": native.ARCHIVE_SHA256,
        "installer_sha256": hashlib.sha256(
            Path(native.__file__).read_bytes()
        ).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    path = tmp_path / "native-hydra-receipt.json"
    path.write_text(json.dumps(receipt))
    assert native.verified_installation(tmp_path)
    binary.write_bytes(b"drift")
    assert not native.verified_installation(tmp_path)
    binary.write_bytes(b"verified")
    receipt["source_commit"] = "b" * 40
    path.write_text(json.dumps(receipt))
    assert not native.verified_installation(tmp_path)
