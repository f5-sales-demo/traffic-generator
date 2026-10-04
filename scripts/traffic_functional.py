"""Functional acceptance from source contracts and observed native responses."""


def verify_functional(scenario: dict, result: dict, responses: list[dict]) -> dict:
    """Require explicit scope, content assertions, and complete native outcomes."""
    contract = scenario.get("functional_contract", {})
    requirements = scenario.get("dispatch_contract", {}).get("requirements", [])
    declared = contract.get("native_response_requirements", [])
    checks = [
        {"id": "declared-functional-scope", "passed": bool(contract.get("behavior"))},
        {
            "id": "read-only-scope",
            "passed": contract.get("mutation_policy") == "read-only"
            and bool(requirements)
            and all(r["method"] in ("GET", "HEAD") for r in requirements),
        },
        {
            "id": "complete-action-contract",
            "passed": bool(declared)
            and set(declared) == {r["id"] for r in requirements},
        },
        {
            "id": "successful-execution",
            "passed": result.get("outcome") == "launched"
            and result.get("dispatch_contract_verified") is True,
        },
        {
            "id": "zero-transport-failures",
            "passed": result.get("transport_failures") == 0
            and result.get("tool_cancellations") == 0,
        },
    ]
    for requirement in requirements:
        identifier = requirement["id"]
        events = [
            e
            for e in responses
            if e.get("scenario") == scenario["id"]
            and e.get("kind") == "scenario"
            and identifier in e.get("matched_requirements", [])
        ]
        specification = requirement.get("response_contract", {})
        content_declared = bool(specification.get("content_type")) and any(
            specification.get(key)
            for key in (
                "text_contains",
                "json_equals",
                "json_keys",
                "json_nonempty_lists",
                "json_document_equals",
                "graphql_data_field",
                "graphql_response_fields",
            )
        )
        checks.append(
            {
                "id": identifier,
                "observed": len(events),
                "passed": identifier in declared
                and content_declared
                and len(events) >= requirement.get("minimum_dispatches", 1)
                and all(
                    e.get("upstream_dispatched") is True
                    and not e.get("transport_error")
                    and e.get("status") in requirement.get("expected_statuses", [])
                    and e.get("response_assertions", {}).get(identifier) is True
                    for e in events
                ),
            }
        )
    return {
        "passed": all(check["passed"] for check in checks),
        "behavior": contract.get("behavior"),
        "checks": checks,
        "control_attribution": "separate WAAP evidence required",
    }
