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
                    {"access_token": "customer"},
                    {"access_token": "chef"},
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
            foreign_namespace = "foreign"
            owned_namespace = "tgen-abcdef0"
            receipt.write_text(
                json.dumps(
                    {
                        "namespace": foreign_namespace,
                        "host_link": "eth0",
                        "chain": "INPUT",
                    }
                )
            )
            with patch("cleanup_network.subprocess.run") as run:
                with pytest.raises(ValueError, match="invalid task-owned"):
                    cleanup(root)
                run.assert_not_called()
            receipt.write_text(
                json.dumps(
                    {
                        "namespace": owned_namespace,
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
            response.read.return_value = b'{"data": []}'
            response.getheader.return_value = "application/json"
            boundary.request("www.example.test")
        assert boundary.state.benign["benign_requests"] == 1
        assert boundary.state.benign["benign_completed"] == 1
        assert boundary.state.benign["benign_success"] == 1
        with (
            patch("traffic_network.subprocess.run"),
            patch("traffic_network.shutil.rmtree"),
        ):
            boundary.__exit__(None, None, None)

    def test_benign_rotation_dispatches_each_application_once(self):
        boundary = NetworkBoundary(
            ROOT, {"domains": ["www.example.test", "api.example.test"]}, ROOT
        )
        with patch("traffic_network.http.client.HTTPSConnection") as connection:
            connection.return_value.getresponse.return_value.status = 200
            connection.return_value.getresponse.return_value.getheader.return_value = (
                "application/json"
            )
            connection.return_value.getresponse.return_value.read.return_value = (
                b'{"data": []}'
            )
            for _ in range(9):
                boundary.request("www.example.test")
            paths = [
                call.args[1] for call in connection.return_value.request.call_args_list
            ]
        assert len(set(paths)) == 9
        assert all(
            count == 1
            for count in boundary.state.benign["benign_per_application"].values()
        )
        with (
            patch("traffic_network.subprocess.run"),
            patch("traffic_network.shutil.rmtree"),
        ):
            boundary.__exit__(None, None, None)

    def test_stalled_gateway_fails_supervisor_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp)
            boundary = NetworkBoundary(
                ROOT, {"domains": ["www.example.test", "api.example.test"]}, runtime
            )
            boundary.state.proxy_metrics.write_text(json.dumps({"updated": 1}))
            assert not boundary.healthy()
            with (
                patch("traffic_network.subprocess.run"),
                patch("traffic_network.shutil.rmtree"),
            ):
                boundary.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()


class ProxyImportTests(unittest.TestCase):
    """Installed proxy helpers are discoverable independently of caller cwd."""

    def test_proxy_environment_contains_the_immutable_helper_directory(self):
        """The proxy must import dispatch matchers from the installed source."""
        source = (ROOT / "scripts/traffic_network.py").read_text()
        assert 'PYTHONPATH=str(self.root / "scripts")' in source


def test_benign_200_wrong_landing_page_is_not_success():
    boundary = NetworkBoundary(
        ROOT, {"domains": ["www.example.test", "api.example.test"]}, ROOT
    )
    with patch("traffic_network.http.client.HTTPSConnection") as connection:
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.getheader.return_value = "text/html"
        response.read.return_value = b"Origin Server"
        boundary.request("www.example.test")
    assert boundary.state.benign["benign_success"] == 0
    with (
        patch("traffic_network.subprocess.run"),
        patch("traffic_network.shutil.rmtree"),
    ):
        boundary.__exit__(None, None, None)
