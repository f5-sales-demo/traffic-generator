#!/usr/bin/env python3
"""Explicit traffic catalog, strict readiness, and side-effect-free discovery."""

import argparse
import json
import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path

MAX_SCENARIO_SECONDS = 900


def validate_catalog(root: Path, catalog: dict) -> None:
    """Reject missing entrypoints, duplicate IDs, and broken execution order."""
    if catalog.get("schema_version") != 1:
        msg = "unsupported catalog schema"
        raise ValueError(msg)
    numbered = {
        str(p.relative_to(root))
        for p in (root / "suites").glob("*/[0-9]*")
        if p.is_file()
    }
    seen, recorded = set(), set()
    for scenario in catalog["scenarios"]:
        identifier = scenario["id"]
        if identifier in seen or not set(scenario["after"]) <= seen:
            msg = "duplicate scenario or missing ordered dependency"
            raise ValueError(msg)
        seen.add(identifier)
        path = root / scenario["entrypoint"]
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            msg = "missing or escaped scenario entrypoint"
            raise ValueError(msg)
        if scenario["kind"] != "csd-browser":
            recorded.add(scenario["entrypoint"])
        if (
            scenario["timeout_seconds"] > MAX_SCENARIO_SECONDS
            or scenario["timeout_seconds"] <= 0
        ):
            msg = "scenario deadline must be within fifteen minutes"
            raise ValueError(msg)
    if not numbered <= recorded:
        msg = "numbered executable missing from catalog"
        raise ValueError(msg)
    browser_names = re.findall(
        r"scenario\(\{\s*name: '([a-z0-9-]+)'",
        (root / "suites/csd-violations/scenarios.mjs").read_text(),
    )
    if set(browser_names) != {
        s["scenario"] for s in catalog["scenarios"] if s["kind"] == "csd-browser"
    }:
        msg = "CSD scenario catalog is incomplete"
        raise ValueError(msg)
    for relative in catalog["support_files"]:
        if not (root / relative).is_file():
            msg = "required support file missing"
            raise ValueError(msg)


def load_catalog(root: Path) -> dict:
    """Read and validate the checked-in catalog."""
    catalog = json.loads((root / "suites/catalog.json").read_text())
    validate_catalog(root, catalog)
    return catalog


def readiness(
    root: Path, catalog: dict, find_tool: Callable[[str], str | None] = shutil.which
) -> dict:
    """Missing dependencies are failures, never passing skips."""
    validate_catalog(root, catalog)
    tools = set(catalog["required_tools"]) | {
        tool
        for scenario in catalog["scenarios"]
        for tool in scenario["dependencies"]
        if tool not in ("playwright", "chromium")
    }
    missing = sorted(t for t in tools if not find_tool(t))
    return {
        "ready": not missing,
        "missing_tools": missing,
        "scenario_count": len(catalog["scenarios"]),
    }


def main() -> int:
    """Preserve suite invocation while exposing ordered catalog discovery."""
    parser = argparse.ArgumentParser()
    parser.add_argument("suite")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    catalog = load_catalog(root)
    if args.suite not in catalog["suites"] and args.suite != "catalog":
        parser.error("unknown suite")
    scenarios = [
        s
        for s in catalog["scenarios"]
        if args.suite == "catalog" or s["suite"] == args.suite
    ]
    if args.dry_run:
        print(json.dumps({"schema_version": 1, "scenarios": scenarios}))
        return 0
    # Continuous and one-pass execution share a single enforced network boundary.
    from traffic_runtime import (  # noqa: PLC0415 - avoid catalog/runtime import cycle
        run,
        run_nested,
    )

    if os.environ.get("TGEN_INHERITED_BOUNDARY") == "1":
        return run_nested(root, scenarios)
    return run(
        root,
        scenarios,
        Path(
            os.environ.get(
                "CATALOG_CONFIG", "/opt/traffic-generator/catalog-config.json"
            )
        ),
        continuous=False,
    )


if __name__ == "__main__":
    raise SystemExit(main())
