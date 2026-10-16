"""Restore declared fixtures after execution, including interrupted native family jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from traffic_network import NetworkBoundary


def recover_fixtures(
    boundary: NetworkBoundary,
    scenario: dict,
    result: dict,
    directory: Path,
    domain: str,
    environment: dict,
) -> None:
    """Keep each declared recovery mandatory independently of the attack outcome."""
    if scenario.get("fixture_contract", {}).get("restore_signup"):
        result["signup_restoration"] = boundary.recover_signup(directory)
        if not result["signup_restoration"]:
            result["outcome"] = "fixture_failure"
    if scenario.get("fixture_contract", {}).get("restore_pastes"):
        result["paste_restoration"] = boundary.recover_pastes(
            directory, domain, environment
        )
        if not result["paste_restoration"]:
            result["outcome"] = "fixture_failure"
    if scenario.get("fixture_contract", {}).get("order_restore"):
        result["order_restoration"] = boundary.order_fixture(directory, "restore")
        if not result["order_restoration"]:
            result["outcome"] = "fixture_failure"
    if (
        scenario.get("fixture_contract", {}).get("family_restore")
        and not (directory / "family-restoration.json").is_file()
        and not boundary.recover_family(
            directory, scenario["fixture_contract"]["family_restore"]
        )
    ):
        result["outcome"] = "fixture_failure"
