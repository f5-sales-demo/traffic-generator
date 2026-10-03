"""Variable load scenarios require their declared levels, samples and cleanup."""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_dispatch import verify_workload


def test_ramp_requires_all_levels_with_requests_and_cleanup():
    contract = {"levels": [1, 10, 20], "minimum_requests": 2}
    receipt: dict[str, Any] = {
        "levels": [{"concurrency": 1, "requests": 2, "transport_failures": 0}],
        "cleanup": True,
    }
    assert not verify_workload(contract, receipt)["passed"]
    receipt["levels"] += [
        {"concurrency": 10, "requests": 2, "transport_failures": 0},
        {"concurrency": 20, "requests": 2, "transport_failures": 0},
    ]
    assert verify_workload(contract, receipt)["passed"]
    receipt["cleanup"] = False
    assert not verify_workload(contract, receipt)["passed"]
