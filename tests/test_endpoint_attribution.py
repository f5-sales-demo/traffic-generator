"""Endpoint attribution requires exact event, policy and server request identity."""

import json

from traffic_security import endpoint_attribution


def test_exact_endpoint_rule_and_request_are_required(tmp_path):
    response: dict = {
        "scenario": "api-protection-verify/03-protection-deny",
        "domain": "www.example.test",
        "path": "/httpbin/anything/admin",
        "method": "POST",
        "status": 403,
        "synthetic_identity": "showcase-" + "a" * 32 + "-request",
        "sent_at": 10.0,
        "received_at": 11.0,
        "upstream_dispatched": True,
        "payload_sha256": "a" * 64,
        "response_sha256": "b" * 64,
    }
    scope = {
        "namespace": "example-waap",
        "loadbalancer": "example-waap",
        "domain": response["domain"],
    }
    event: dict = {
        "req_id": "synthetic-request",
        "namespace": scope["namespace"],
        "vh_name": "ves-io-http-loadbalancer-example-waap",
        "domain": response["domain"],
        "req_path": response["path"],
        "method": "POST",
        "user": "Header-X-Mud-User-" + response["synthetic_identity"],
        "rsp_code": "403",
        "time": "1970-01-01T00:00:10.500Z",
        "action": "block",
        "sec_event_type": "api_sec_event",
        "sec_event_name": "API Protection Rule",
        "policy_hits": {
            "policy_hits": [
                {
                    "result": "deny",
                    "policy": "ves-io-http-loadbalancer-api-protection-example-waap",
                    "policy_rule": "ves-io-service-policy-ves-io-http-loadbalancer-api-protection-example-waap-api-protection-0",
                    "policy_namespace": "example-waap",
                }
            ]
        },
    }
    result = {"source_commit": "c" * 40, "artifact_sha256": "d" * 64}
    evidence: dict = {
        **result,
        "scope": scope,
        "clock_bounds": [-1, 1],
        "checks": [{"response": response, "access": dict(event), "events": [event]}],
    }
    file = tmp_path / "control-attribution.json"
    file.write_text(json.dumps(evidence))
    assert endpoint_attribution(response, result, tmp_path)
    evidence["checks"][0]["security_request_id"] = event["req_id"]
    evidence["checks"][0]["access"] = None
    file.write_text(json.dumps(evidence))
    assert endpoint_attribution(response, result, tmp_path)
    evidence["checks"][0]["security_request_id"] = "foreign"
    file.write_text(json.dumps(evidence))
    assert not endpoint_attribution(response, result, tmp_path)
    evidence["checks"][0]["security_request_id"] = event["req_id"]
    evidence["checks"][0]["access"] = dict(event)
    event["req_id"] = "foreign"
    file.write_text(json.dumps(evidence))
    assert not endpoint_attribution(response, result, tmp_path)
    event["req_id"] = "synthetic-request"
    event["policy_hits"]["policy_hits"][0]["policy_rule"] = "foreign"
    file.write_text(json.dumps(evidence))
    assert not endpoint_attribution(response, result, tmp_path)
