"""Require native library execution and complete browser cleanup evidence."""

import hashlib
import json
from pathlib import Path

from traffic_dispatch import verify_browser_actions


def verify_csd_libraries(scenario: dict, result: dict, directory: Path) -> dict:
    """A terminal failure cannot count as native library execution."""
    files = list(directory.glob("*/receipt.json"))
    if len(files) != 1:
        return {
            "passed": False,
            "reason": "native browser receipt missing or ambiguous",
        }
    try:
        receipt = json.loads(files[0].read_text())
    except (OSError, ValueError):
        return {"passed": False, "reason": "native browser receipt unreadable"}
    if not isinstance(receipt, dict):
        return {"passed": False, "reason": "native browser receipt malformed"}
    contract = scenario["functional_contract"]
    native = [
        item
        for item in receipt.get("scenarios", [])
        if item.get("name") == scenario["scenario"]
    ]
    if len(native) != 1:
        return {"passed": False, "reason": "native library scenario missing"}
    steps = {step["name"]: step for step in native[0].get("steps", [])}
    execution = all(
        steps.get(name, {}).get("evidence", {}).get(field) == "finished"
        for name, fields in contract["native_library_steps"].items()
        for field in fields
    )
    screenshots = []
    for step in steps.values():
        specification = step.get("screenshot", {})
        name = specification.get("path", "")
        path = files[0].parent / name
        screenshots.append(
            bool(name)
            and Path(name).name == name
            and path.is_file()
            and hashlib.sha256(path.read_bytes()).hexdigest()
            == specification.get("sha256")
        )
    return {
        "passed": execution
        and bool(screenshots)
        and all(screenshots)
        and verify_browser_actions(scenario["browser_contract"], receipt)["passed"]
        and receipt.get("runtime", {}).get("sourceCommit")
        == result.get("source_commit")
        and receipt.get("runtime", {}).get("artifactDigest")
        == result.get("artifact_sha256")
        and receipt.get("runtime", {}).get("csdEnabled") is False
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": contract["behavior"],
        "native_libraries_executed": execution,
        "screenshots_verified": all(screenshots),
        "claim": "native browser simulation only; CSD enforcement disabled",
    }
