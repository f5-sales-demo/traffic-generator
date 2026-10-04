"""Client isolation is verified from returned synthetic identity markers."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_multiclient import APPLICATION_PATHS, client, identity_matches


def test_another_clients_cookie_or_forwarded_identity_fails():
    headers = {
        "True-Client-Ip": "192.0.2.17",
        "Fastly-Client-Ip": "192.0.2.17",
        "Cookie": "tgen_client=client-17",
    }
    assert identity_matches(headers, "192.0.2.17", "client-17")
    assert not identity_matches(headers, "192.0.2.18", "client-17")
    assert not identity_matches(headers, "192.0.2.17", "client-18")


def test_each_independent_client_dispatches_all_nine_applications():
    def native_response(url, _headers=None, **_options):
        return (
            200,
            {"content-type": "application/json"},
            json.dumps(
                {
                    "headers": {
                        "True-Client-IP": "192.0.2.1",
                        "Fastly-Client-IP": "192.0.2.1",
                        "Cookie": "tgen_client=client-0",
                    }
                }
            ).encode(),
        )

    with patch("traffic_multiclient.request", side_effect=native_response) as native:
        with patch("traffic_multiclient.content_identity", return_value=True):
            result = client("www.example.test", 0)
        paths = [
            call.args[0].removeprefix("https://www.example.test")
            for call in native.call_args_list
        ]
    assert set(APPLICATION_PATHS).issubset(paths)
    assert len(result["application_checks"]) == 9
    assert result["passed"]
