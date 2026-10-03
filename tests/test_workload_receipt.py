"""Variable load scenarios require their declared levels, samples and cleanup."""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_dispatch import verify_workload
from traffic_workload import content_identity


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


def test_wrong_content_200_is_a_workload_failure():
    assert not content_identity("/vampi/", "text/html", b"Origin Server")
    assert content_identity("/vampi/", "application/json", b'{"message":"VAmPI"}')


def test_workload_requires_actual_concurrency_and_connection_behavior():
    specification = {"levels": [10], "minimum_requests": 20, "verify_behavior": True}
    receipt: dict[str, Any] = {
        "levels": [
            {
                "concurrency": 10,
                "maximum_active": 1,
                "requests": 20,
                "transport_failures": 0,
                "content_failures": 0,
                "persistent": True,
                "connections_created": 20,
            }
        ],
        "cleanup": True,
    }
    assert not verify_workload(specification, receipt)["passed"]
    receipt["levels"][0].update(maximum_active=10, connections_created=10)
    assert verify_workload(specification, receipt)["passed"]


def test_duration_cutoff_cannot_substitute_for_completed_counted_requests():
    specification = {"levels": [20], "minimum_requests": 100, "verify_behavior": True}
    receipt = {
        "levels": [
            {
                "concurrency": 20,
                "maximum_active": 20,
                "requests": 99,
                "transport_failures": 0,
                "content_failures": 0,
                "persistent": True,
                "connections_created": 20,
            }
        ],
        "cleanup": True,
    }
    assert not verify_workload(specification, receipt)["passed"]
