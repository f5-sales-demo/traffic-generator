"""Observe an isolated native scanner process group and require actual cleanup."""

import os
import signal
import subprocess
import time
from pathlib import Path


def group_members(group: int) -> list[int]:
    """Read Linux process groups independently of the scanner exit status."""
    members = []
    for entry in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = entry.read_text().rsplit(") ", 1)[1].split()
            if int(fields[2]) == group and fields[0] != "Z":
                members.append(int(entry.parent.name))
        except (OSError, ValueError, IndexError):
            continue
    return sorted(members)


def run_scanner(argv: list[str], environment: dict, log: Path, deadline: int) -> dict:
    """Record observed processes; a timeout or surviving descendant fails acceptance."""
    observed = set()
    started = time.monotonic()
    timed_out = False
    with log.open("w") as stream:
        log.chmod(0o600)
        with subprocess.Popen(  # noqa: S603 - caller supplies scoped native argv
            argv,
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        ) as process:
            while process.poll() is None:
                observed.update(group_members(process.pid))
                if time.monotonic() - started >= deadline:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGTERM)
                    break
                time.sleep(0.1)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            remaining = group_members(process.pid)
            if remaining:
                os.killpg(process.pid, signal.SIGKILL)
                for _ in range(50):
                    if not group_members(process.pid):
                        break
                    time.sleep(0.1)
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "observed_process_count": len(observed),
        "remaining_before_cleanup": remaining,
        "remaining_after_cleanup": group_members(process.pid),
        "connections_closed": bool(observed) and not remaining,
        "cleanup_basis": "observed Linux process group absent; owned socket descriptors closed",
        "elapsed_seconds": time.monotonic() - started,
    }
