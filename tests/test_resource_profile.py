"""Self-profile coverage requires measurements during load, not only HTTP counts."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from traffic_dispatch import verify_workload
from traffic_profile import sample_resources, verify_profile


def test_resource_samples_include_cpu_memory_disk_network_sockets_and_descriptors():
    sample = sample_resources()
    assert sample["memory_total_bytes"] >= sample["memory_available_bytes"] > 0
    assert sample["cpu_total_ticks"] >= sample["cpu_idle_ticks"] > 0
    assert sample["network_rx_bytes"] >= 0
    assert sample["disk_read_sectors"] >= 0
    assert sample["process_fds"] > 0
    assert sample["tcp_established"] >= 0


def test_profile_requires_baseline_under_load_and_cleanup():
    sample = sample_resources()
    profile = {
        "samples": [
            {**sample, "phase": phase}
            for phase in ("baseline", "under-load", "cleanup")
        ]
    }
    assert verify_profile(profile)
    profile["samples"].pop(1)
    assert not verify_profile(profile)
    assert not verify_workload(
        {"levels": [], "minimum_requests": 1, "resource_profile": True},
        {"levels": [], "cleanup": True},
    )["passed"]


def test_each_declared_connection_churn_batch_is_required():
    contract = {"levels": [20], "minimum_requests": 20, "batches": [20, 50, 100]}
    sample = {
        "concurrency": 20,
        "requests": 100,
        "transport_failures": 0,
        "content_failures": 0,
        "connections_closed": True,
    }
    assert not verify_workload(contract, {"levels": [sample], "cleanup": True})[
        "passed"
    ]
    samples = [{**sample, "requests": count} for count in (20, 50, 100)]
    assert verify_workload(contract, {"levels": samples, "cleanup": True})["passed"]


def test_connection_comparison_requires_reused_and_fresh_connections():
    contract = {
        "levels": [1],
        "minimum_requests": 100,
        "connection_modes": [True, False],
    }
    persistent = {
        "concurrency": 1,
        "requests": 100,
        "transport_failures": 0,
        "content_failures": 0,
        "persistent": True,
        "connections_created": 1,
    }
    assert not verify_workload(contract, {"levels": [persistent], "cleanup": True})[
        "passed"
    ]
    fresh = {**persistent, "persistent": False, "connections_created": 100}
    assert verify_workload(contract, {"levels": [persistent, fresh], "cleanup": True})[
        "passed"
    ]
    fresh["connections_created"] = 1
    assert not verify_workload(
        contract, {"levels": [persistent, fresh], "cleanup": True}
    )["passed"]
