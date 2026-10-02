"""Installer fails before promotion on digest mismatch or unsafe archive content."""

import importlib.util
import io
import pathlib
import tempfile
import unittest
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

    def test_floating_source_rejected_before_download(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(installer, "urlopen") as fetch,
        ):
            with pytest.raises(ValueError, match="exact source"):
                installer.install("main", "b" * 64, pathlib.Path(tmp))
            fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
