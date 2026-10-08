"""Only exact request-bound violations of the effective immutable schema qualify."""

import hashlib
import json
import re


def configured_schema(evidence: dict, scope: dict) -> bool:
    """Validate the active listener reference, enforced properties and exact fixture content."""
    try:
        proof = evidence["schema"]
        listener, definition, fixture = (
            proof[key] for key in ("listener", "definition", "fixture")
        )
        namespace, lb = scope["namespace"], scope["loadbalancer"]
        if (
            listener["metadata"]["name"] != lb
            or listener["metadata"]["namespace"] != namespace
        ):
            return False
        spec = listener["spec"]["api_specification"]
        ref = spec["api_definition"]
        if (
            ref["name"] != lb + "-api-def"
            or ref["namespace"] != namespace
            or definition["metadata"]["name"] != ref["name"]
            or definition["metadata"]["namespace"] != namespace
        ):
            return False
        active = spec["validation_all_spec_endpoints"]["validation_mode"][
            "validation_mode_active"
        ]
        if (
            "enforcement_block" not in active
            or "enforcement_report" in active
            or "PROPERTY_HTTP_BODY" not in active["request_validation_properties"]
        ):
            return False
        paths = definition["spec"]["swagger_specs"]
        meta = fixture["metadata"]
        name = meta["name"]
        content = fixture["string_value"]
        exact = (
            "/api/object_store/namespaces/"
            + namespace
            + "/stored_objects/swagger/"
            + name
            + "/"
            + meta["version"]
        )
        expected_names = (
            {
                "showcase-form-native",
                "showcase-form-" + hashlib.sha256(content.encode()).hexdigest()[:32],
            }
            if isinstance(content, str)
            else set()
        )
        name_valid = (
            name in expected_names
            and re.fullmatch(
                r"(?:showcase-form-native|showcase-form-[a-f0-9]{32})", name
            )
            is not None
        )
        if (
            not name_valid
            or paths != [exact]
            or meta["version"].lower() == "latest"
            or meta["namespace"] != namespace
        ):
            return False
        schema = json.loads(fixture["string_value"])["paths"]["/httpbin/post"]["post"][
            "requestBody"
        ]["content"]["application/json"]["schema"]
        return (
            "demo_id" in schema["required"]
            and schema["properties"]["demo_id"]["type"] == "string"
        )
    except (KeyError, TypeError, ValueError):
        return False


def schema_violation(event: dict) -> bool:
    """Require the actual request-body demo_id violation, never a generic API block."""
    return (
        event.get("action") == "block"
        and event.get("sec_event_type") == "api_sec_event"
        and event.get("sec_event_name") == "OpenAPI Validation Failure"
        and event.get("oas_req_status") == "OpenAPIViolation"
        and event.get("api_endpoint") == "/httpbin/post"
        and any(
            isinstance(row, dict)
            and row.get("context") == "Request"
            and row.get("field") == "demo_id"
            and row.get("property") == "HTTP Body"
            and any(
                word in row.get("description", "").lower()
                for word in ("missing", "required", "string")
            )
            for row in event.get("violations", [])
        )
    )
