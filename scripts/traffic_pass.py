"""Create exact source-bound pass receipts with measured traffic deltas."""

import hashlib
from pathlib import Path

from catalog_pass_receipt import catalog_pass_receipt
from traffic_catalog import load_catalog


def current_pass_receipt(
    root: Path,
    scenarios: list[dict],
    started: float,
    active: Path,
    receipts: list[dict],
    config: dict,
    traffic: dict,
) -> dict:
    """Resolve source digests outside the supervisor's lifecycle state."""
    digests = {
        item["id"]: hashlib.sha256((root / item["entrypoint"]).read_bytes()).hexdigest()
        for item in load_catalog(root)["scenarios"]
    }
    return catalog_pass_receipt(
        active.name,
        started,
        receipts,
        {item["id"]: digests[item["id"]] for item in scenarios},
        digests,
        config,
        traffic,
    )
