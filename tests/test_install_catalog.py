"""Installer fails before promotion on digest mismatch or unsafe archive content."""
import importlib.util
import io
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('catalog_installer', ROOT / 'scripts/install-catalog.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_digest_mismatch_preserves_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            current = root / 'current'
            current.write_text('existing')
            with patch.object(installer, 'urlopen', return_value=io.BytesIO(b'wrong artifact')):
                with self.assertRaisesRegex(ValueError, 'digest'):
                    installer.install('a' * 40, 'b' * 64, root)
            self.assertEqual(current.read_text(), 'existing')
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['current'])

    def test_floating_source_rejected_before_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(installer, 'urlopen') as fetch:
                with self.assertRaisesRegex(ValueError, 'exact source'):
                    installer.install('main', 'b' * 64, pathlib.Path(tmp))
                fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
