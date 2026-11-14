"""Private Linux resource measurements for the declared self-profiling workload."""

import os
import time
from pathlib import Path


def sample_resources() -> dict:
    """Read counters without retaining host, interface, disk or process identities."""
    cpu = [
        int(value)
        for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    ]
    memory = {
        line.split(":")[0]: int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.split()[1].isdigit()
    }
    network = [
        line.split(":", 1)[1].split()
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]
    ]
    disks = [line.split() for line in Path("/proc/diskstats").read_text().splitlines()]
    sockets = [
        line.split()[3]
        for name in ("tcp", "tcp6")
        for line in Path("/proc/net", name).read_text().splitlines()[1:]
    ]
    return {
        "monotonic": time.monotonic(),
        "cpu_total_ticks": sum(cpu),
        "cpu_idle_ticks": cpu[3],
        "load_average": list(os.getloadavg()),
        "memory_total_bytes": memory["MemTotal"],
        "memory_available_bytes": memory["MemAvailable"],
        "network_rx_bytes": sum(int(row[0]) for row in network),
        "network_tx_bytes": sum(int(row[8]) for row in network),
        "disk_read_sectors": sum(int(row[5]) for row in disks),
        "disk_written_sectors": sum(int(row[9]) for row in disks),
        "tcp_established": sockets.count("01"),
        "tcp_time_wait": sockets.count("06"),
        "process_fds": len(list(Path("/proc/self/fd").iterdir())),
    }


def verify_profile(receipt: dict) -> bool:
    """Require finite counter samples before, during and after workload cleanup."""
    samples = receipt.get("samples", [])
    fields = {
        "cpu_total_ticks",
        "cpu_idle_ticks",
        "memory_total_bytes",
        "memory_available_bytes",
        "network_rx_bytes",
        "network_tx_bytes",
        "disk_read_sectors",
        "disk_written_sectors",
        "tcp_established",
        "tcp_time_wait",
        "process_fds",
    }
    return {sample.get("phase") for sample in samples} >= {
        "baseline",
        "under-load",
        "cleanup",
    } and all(
        all(
            isinstance(sample.get(field), int) and sample[field] >= 0
            for field in fields
        )
        and sample["memory_total_bytes"] > 0
        and sample["process_fds"] > 0
        for sample in samples
    )
