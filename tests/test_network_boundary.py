"""Network worker and namespace cleanup regressions without live targets."""

import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cleanup_network import cleanup  # noqa: E402 - scripts under test
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

    def test_cleanup_refuses_foreign_namespace_and_removes_only_owned_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            receipt = root / "network-owner.json"
            receipt.write_text(
                json.dumps(
                    {"namespace": "foreign", "host_link": "eth0", "chain": "INPUT"}
                )
            )
            with patch("cleanup_network.subprocess.run") as run:
                with pytest.raises(ValueError, match="invalid task-owned"):
                    cleanup(root)
                run.assert_not_called()
            receipt.write_text(
                json.dumps(
                    {
                        "namespace": "tgen-abcdef0",
                        "host_link": "tghabcdef0",
                        "chain": "TGENABCDEF0",
                    }
                )
            )
            with patch("cleanup_network.subprocess.run") as run:
                cleanup(root)
                assert run.call_count == 8
                assert all(call.args[0][-1] != "INPUT" for call in run.call_args_list)
            assert not receipt.exists()

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

    def test_benign_requests_are_counted_at_dispatch_and_completion(self):
        boundary = NetworkBoundary(
            ROOT, {"domains": ["www.example.test", "api.example.test"]}, ROOT
        )
        with patch("traffic_network.http.client.HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            boundary.request("www.example.test")
        assert boundary.state.benign["benign_requests"] == 1
        assert boundary.state.benign["benign_completed"] == 1
        assert boundary.state.benign["benign_success"] == 1
        with (
            patch("traffic_network.subprocess.run"),
            patch("traffic_network.shutil.rmtree"),
        ):
            boundary.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
