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
    binary.chmod(0o755)
    receipt = {
        "source_commit": native.COMMIT,
        "archive_sha256": native.ARCHIVE_SHA256,
        "installer_sha256": hashlib.sha256(
            Path(native.__file__).read_bytes()
        ).hexdigest(),
        "adapter_sha256": hashlib.sha256(
            Path(native.__file__).with_name("wrk_drain_adapter.py").read_bytes()
        ).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    (tmp_path / "native-wrk-receipt.json").write_text(json.dumps(receipt))
    with patch("install_native_wrk.urlopen") as fetch:
        assert install(tmp_path) == receipt
    fetch.assert_not_called()


def test_reproducible_defaults_and_module_paths_preserve_native_source(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    lua = source / "wrk.lua"
    suffix = "\nfunction wrk.request() return wrk.method end\nreturn wrk\n"
    lua.write_text(native.DEFAULT_TABLE + suffix)
    makefile = tmp_path / "Makefile"
    makefile.write_text(
        "PREFIX=$(abspath $(ODIR)) BUILDMODE=static install\n"
        'PATH="obj/bin:$(PATH)" luajit -b "$(CURDIR)/$<" "$(CURDIR)/$@"\n'
    )
    native.reproducible_source(tmp_path)
    assert lua.read_text() == native.DEFAULT_ASSIGNMENTS + suffix
    assert "PREFIX=/usr/local" in makefile.read_text()
    assert 'INSTALL_LIB="$(abspath $(ODIR))/lib"' in makefile.read_text()
    assert (
        'LUA_PATH="$(CURDIR)/obj/share/luajit-2.1.0-beta3/?.lua;;"'
        in makefile.read_text()
    )
    with pytest.raises(ValueError, match="anchor mismatch"):
        native.reproducible_source(tmp_path)


@pytest.mark.parametrize(
    "drift", ["binary", "mode", "symlink", "source", "installer", "adapter"]
)
def test_native_readback_rejects_drift_without_silent_reuse(tmp_path, drift):
    binary = tmp_path / "bin/wrk"
    binary.parent.mkdir()
    binary.write_bytes(b"verified")
    binary.chmod(0o755)
    receipt = {
        "source_commit": native.COMMIT,
        "archive_sha256": native.ARCHIVE_SHA256,
        "installer_sha256": hashlib.sha256(
            Path(native.__file__).read_bytes()
        ).hexdigest(),
        "adapter_sha256": hashlib.sha256(
            Path(native.__file__).with_name("wrk_drain_adapter.py").read_bytes()
        ).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    path = tmp_path / "native-wrk-receipt.json"
    path.write_text(json.dumps(receipt))
    assert native.verified_installation(tmp_path)
    if drift == "binary":
        binary.write_bytes(b"drift")
    elif drift == "mode":
        binary.chmod(0o644)
    elif drift == "symlink":
        target = binary.with_name("other")
        binary.rename(target)
        binary.symlink_to(target)
    else:
        key = {
            "source": "source_commit",
            "installer": "installer_sha256",
            "adapter": "adapter_sha256",
        }[drift]
        receipt[key] = "b" * 64
        path.write_text(json.dumps(receipt))
    assert not native.verified_installation(tmp_path)
    with (
        patch("install_native_wrk.urlopen", return_value=io.BytesIO(b"corrupt")),
        pytest.raises(ValueError, match="digest mismatch"),
    ):
        install(tmp_path)
