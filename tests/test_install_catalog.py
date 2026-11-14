"""Installer fails before promotion on digest mismatch or unsafe archive content."""

import hashlib
import importlib.util
import io
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
from typing import cast
from unittest.mock import patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "catalog_installer", ROOT / "scripts/install_catalog.py"
)
assert SPEC is not None
assert SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_digest_mismatch_preserves_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            current = root / "current"
            current.write_text("existing")
            with (
                patch.object(
                    installer, "urlopen", return_value=io.BytesIO(b"wrong artifact")
                ),
                pytest.raises(ValueError, match="digest"),
            ):
                installer.install("a" * 40, "b" * 64, root)
            assert current.read_text() == "existing"
            assert sorted(p.name for p in root.iterdir()) == ["current"]

    def test_modified_immutable_source_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            commit = "a" * 40
            installed = root / ("source-" + commit)
            installed.mkdir()
            (installed / "source.txt").write_text("modified")
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                entry = tarfile.TarInfo("traffic-generator-" + commit + "/source.txt")
                content = b"verified-source"
                entry.size = len(content)
                tar.addfile(entry, io.BytesIO(content))
            payload = archive.getvalue()
            with (
                patch.object(installer, "urlopen", return_value=io.BytesIO(payload)),
                patch.object(installer.subprocess, "run"),
                pytest.raises(ValueError, match="differs"),
            ):
                installer.install(commit, hashlib.sha256(payload).hexdigest(), root)
            assert (installed / "source.txt").read_text() == "modified"

    def test_floating_source_rejected_before_download(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(installer, "urlopen") as fetch,
        ):
            with pytest.raises(ValueError, match="exact source"):
                installer.install("main", "b" * 64, pathlib.Path(tmp))
            fetch.assert_not_called()

    def test_extra_executable_in_existing_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            commit = "a" * 40
            installed = root / ("source-" + commit)
            installed.mkdir()
            (installed / "source.txt").write_bytes(b"verified-source")
            (installed / "extra.sh").write_text("unverified executable")
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                entry = tarfile.TarInfo("traffic-generator-" + commit + "/source.txt")
                entry.size = len(b"verified-source")
                tar.addfile(entry, io.BytesIO(b"verified-source"))
            payload = archive.getvalue()
            with (
                patch.object(installer, "urlopen", return_value=io.BytesIO(payload)),
                patch.object(installer.subprocess, "run"),
                pytest.raises(ValueError, match="differs"),
            ):
                installer.install(commit, hashlib.sha256(payload).hexdigest(), root)

    def test_service_install_uses_verified_source_and_stays_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            destination = root / "catalog"
            source = destination / "current/scripts"
            source.mkdir(parents=True)
            for name in ("tgen-control", "tgen-continuous.service"):
                (source / name).write_bytes((ROOT / "scripts" / name).read_bytes())
            installer.install_service(destination, root / "system")
            control = root / "system/usr/local/bin/tgen-control"
            assert str(destination) in control.read_text()
            assert control.stat().st_mode & 0o777 == 0o755
            assert (
                "ExecStart="
                in (
                    root / "system/etc/systemd/system/tgen-continuous.service"
                ).read_text()
            )


def test_native_service_install_preserves_exact_source_inventory(tmp_path):
    destination = tmp_path / "catalog"
    source = destination / "current/scripts"
    source.mkdir(parents=True)
    for name in ("tgen-control", "tgen-continuous.service"):
        (source / name).write_text("declared service artifact")
    for name in ("install_native_wrk.py", "install_native_hydra.py"):
        (source / name).write_text("import inventory_probe\n")
    (source / "inventory_probe.py").write_text("NATIVE_SOURCE = 'verified'\n")
    expected = {str(path.relative_to(source)) for path in source.rglob("*")}

    class PrivateSystemRoot:
        def __hash__(self):
            return hash(pathlib.Path("/"))

        def __truediv__(self, relative):
            return tmp_path / "system" / relative

        def __eq__(self, other):
            return other == pathlib.Path("/")

    real_run = subprocess.run

    def run_native_only(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            return subprocess.CompletedProcess(argv, 0)
        return real_run(argv, check=kwargs.pop("check", False), **kwargs)

    with patch.object(installer.subprocess, "run", side_effect=run_native_only):
        installer.install_service(destination, cast(pathlib.Path, PrivateSystemRoot()))
        installer.install_service(destination, cast(pathlib.Path, PrivateSystemRoot()))
    assert {str(path.relative_to(source)) for path in source.rglob("*")} == expected


if __name__ == "__main__":
    unittest.main()
