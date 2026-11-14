"""File-type WAF proof requires enabled policy and the exact requested extension."""

import json

from traffic_security import waf_attribution


def test_enabled_filetype_control_is_exactly_request_bound(tmp_path):
    response: dict = {
        "scenario": "synthetic/file",
        "domain": "www.example.com",
        "path": "/juice-shop/ftp/package.json.bak",
        "method": "GET",
        "status": 403,
        "synthetic_identity": "showcase-opaque-request",
        "sent_at": 10.0,
        "received_at": 11.0,
        "payload_sha256": "a" * 64,
        "response_sha256": "b" * 64,
        "upstream_dispatched": True,
    }
    event: dict = {
        "req_id": "native-request",
        "namespace": "example-waap",
        "vh_name": "ves-io-http-loadbalancer-example-waap",
        "domain": response["domain"],
        "req_path": response["path"],
        "method": "GET",
        "user": "Header-X-Mud-User-" + response["synthetic_identity"],
        "time": "1970-01-01T00:00:10.500Z",
        "rsp_code": "403",
        "action": "block",
        "sec_event_type": "waf_sec_event",
        "sec_event_name": "WAF",
        "app_firewall_name": "example-waap-waf",
        "enforcement_mode": "Blocking",
        "waf_mode": "block",
        "recommended_action": "block",
        "violations": [
            {
                "name": "VIOL_FILETYPE",
                "context": "request",
                "state": "Enabled",
                "matching_info": "File extension was bak",
            }
        ],
    }
    evidence: dict = {
        "source_commit": "c" * 40,
        "artifact_sha256": "d" * 64,
        "scope": {
            "namespace": "example-waap",
            "loadbalancer": "example-waap",
            "domain": response["domain"],
        },
        "clock_bounds": [-1, 1],
        "firewall": {
            "metadata": {"name": "example-waap-waf", "namespace": "example-waap"},
            "spec": {"blocking": {}, "default_detection_settings": {}},
        },
        "checks": [{"response": response, "access": dict(event), "events": [event]}],
    }
    result = {"source_commit": "c" * 40, "artifact_sha256": "d" * 64}

    def accept():
        (tmp_path / "control-attribution.json").write_text(json.dumps(evidence))
        return waf_attribution(response, result, tmp_path, [])

    assert accept()
    event["violations"][0]["matching_info"] = "File extension was exe"
    assert not accept()
    event["violations"][0]["matching_info"] = "File extension was bak"
    event["violations"][0]["state"] = "Disabled"
    assert not accept()
    event["violations"][0]["state"] = "Enabled"
    event["req_id"] = "other-request"
    assert not accept()
