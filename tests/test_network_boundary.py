"""Network worker and namespace cleanup regressions without live targets."""

import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from traffic_network import NetworkBoundary  # noqa: E402 - scripts under test


class BoundaryTests(unittest.TestCase):
    def test_http_workers_cannot_reconfigure_network(self):
        boundary = NetworkBoundary(
            ROOT, {"domains": ["www.example.test", "api.example.test"]}, ROOT
        )
        command = boundary.wrap(["curl", "https://www.example.test/"])
        assert "setpriv" in command
        assert "--bounding-set=-all" in command
        with (
            patch("traffic_network.subprocess.run"),
            patch("traffic_network.shutil.rmtree"),
        ):
            boundary.__exit__(None, None, None)

    def test_real_fixture_accounts_are_collected_without_origin_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            runtime = root / "runtime"
            runtime.mkdir()
            boundary = NetworkBoundary(
                ROOT, {"domains": ["www.example.test", "api.example.test"]}, runtime
            )
            with patch.object(
                boundary,
                "fixture_login",
                side_effect=[
                    {"auth_token": "vampi"},
                    {"token": "crapi-a"},
                    {"token": "crapi-b"},
                    {"authentication": {"token": "juice"}},
                ],
            ):
                boundary.refresh_fixtures("www.example.test")
            data = json.loads((root / "fixtures.json").read_text())
            assert data["crapi_tokens"] == ["crapi-a", "crapi-b"]
            assert data["vampi_token"] == "vampi"  # noqa: S105 - synthetic mock token
            with (
                patch("traffic_network.subprocess.run"),
                patch("traffic_network.shutil.rmtree"),
            ):
                boundary.__exit__(None, None, None)

    def test_worker_callback_belongs_to_boundary(self):
        boundary = NetworkBoundary(
            ROOT, {"domains": ["www.example.test", "api.example.test"]}, ROOT
        )
        assert callable(boundary.benign_loop)
        assert not hasattr(boundary.state, "benign_loop")
        with (
            patch("traffic_network.subprocess.run"),
            patch("traffic_network.shutil.rmtree"),
        ):
            boundary.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
