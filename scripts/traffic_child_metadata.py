"""Source-bound native child dispatch metadata."""

from pathlib import Path


def child_dispatch(scenario: dict, directory: Path) -> dict:
    """Retain declared functional and fixture contracts for proxy attribution."""
    return {
        "id": scenario["id"],
        "phase": "execution",
        "dispatch_path": str(directory / "dispatch-events.jsonl"),
        "dispatch_contract": scenario.get("dispatch_contract", {}),
        "functional_contract": scenario.get("functional_contract", {}),
        "fixture_contract": scenario.get("fixture_contract", {}),
        "expected_statuses": scenario.get("expected_http_statuses", []),
    }
