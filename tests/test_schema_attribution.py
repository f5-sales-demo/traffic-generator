"""Schema blocks require exact fixture, enforcement, request ID and native field evidence."""

import copy
import json

from traffic_security import schema_attribution


def evidence():
    namespace, lb = "demo", "demo-lb"
    response: dict = {
        "scenario": "synthetic/action",
        "domain": "www.example.test",
        "path": "/httpbin/post",
        "method": "POST",
        "status": 403,
        "synthetic_identity": "showcase-" + "a" * 32 + "-request",
        "sent_at": 10,
        "received_at": 11,
        "payload_sha256": "a" * 64,
        "response_sha256": "b" * 64,
        "upstream_dispatched": True,
    }
    result = {"source_commit": "c" * 40, "artifact_sha256": "d" * 64}
    event = {
        "req_id": "exact",
        "namespace": namespace,
        "vh_name": "ves-io-http-loadbalancer-" + lb,
        "domain": response["domain"],
        "req_path": response["path"],
        "method": "POST",
        "rsp_code": "403",
        "time": "1970-01-01T00:00:10.500Z",
        "user": "Header-X-Mud-User-" + response["synthetic_identity"],
        "action": "block",
        "sec_event_type": "api_sec_event",
        "sec_event_name": "OpenAPI Validation Failure",
        "oas_req_status": "OpenAPIViolation",
        "api_endpoint": "/httpbin/post",
        "violations": [
            {
                "context": "Request",
                "field": "demo_id",
                "property": "HTTP Body",
                "description": 'property "demo_id" is missing',
            }
        ],
    }
    ref = {"name": lb + "-api-def", "namespace": namespace}
    schema = {
        "paths": {
            "/httpbin/post": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "required": ["demo_id"],
                                    "properties": {"demo_id": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    proof = {
        "listener": {
            "metadata": {"name": lb, "namespace": namespace},
            "spec": {
                "api_specification": {
                    "api_definition": ref,
                    "validation_all_spec_endpoints": {
                        "validation_mode": {
                            "validation_mode_active": {
                                "enforcement_block": {},
                                "request_validation_properties": ["PROPERTY_HTTP_BODY"],
                            }
                        }
                    },
                }
            },
        },
        "definition": {
            "metadata": ref,
            "spec": {
                "swagger_specs": [
                    "/api/object_store/namespaces/demo/stored_objects/swagger/showcase-form-native/v1"
                ]
            },
        },
        "fixture": {
            "metadata": {
                "name": "showcase-form-native",
                "namespace": namespace,
                "version": "v1",
            },
            "string_value": json.dumps(schema),
        },
    }
    bundle = {
        **result,
        "scope": {
            "namespace": namespace,
            "loadbalancer": lb,
            "domain": response["domain"],
        },
        "clock_bounds": [-1, 1],
        "schema": proof,
        "checks": [{"response": response, "access": dict(event), "events": [event]}],
    }
    return response, result, bundle


def test_exact_schema_request_and_enforcement_are_required():
    response, result, bundle = evidence()
    assert schema_attribution(response, result, bundle)
    for mode in ("request", "field", "enforcement", "version", "fixture", "source"):
        changed = copy.deepcopy(bundle)
        if mode == "request":
            changed["checks"][0]["events"][0]["req_id"] = "foreign"
        elif mode == "field":
            changed["checks"][0]["events"][0]["violations"][0]["field"] = "unrelated"
        elif mode == "enforcement":
            changed["schema"]["listener"]["spec"]["api_specification"][
                "validation_all_spec_endpoints"
            ]["validation_mode"]["validation_mode_active"] = {"enforcement_report": {}}
        elif mode == "version":
            changed["schema"]["fixture"]["metadata"]["version"] = "latest"
        elif mode == "fixture":
            changed["schema"]["fixture"]["string_value"] = "{}"
        else:
            changed["source_commit"] = "e" * 40
        assert not schema_attribution(response, result, changed)
    response["path"] = "/unrelated"
    assert not schema_attribution(response, result, bundle)
