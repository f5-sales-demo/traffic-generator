"""Shared pacing, private receipts, and scenario process cleanup."""

import contextlib
import json
import os
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path


class Pacer:
    """Serialize actual launches without accumulating burst credit."""

    def __init__(self, rate: float) -> None:
        """Initialize the shared nonbursting clock."""
        self.interval = 1 / rate
        self.lock = threading.Lock()
        self.next = time.monotonic()

    def acquire(self) -> float:
        """Wait for a single launch slot, shared by every nested worker."""
        with self.lock:
            now = time.monotonic()
            if self.next > now:
                time.sleep(self.next - now)
            launched = time.monotonic()
            self.next = launched + self.interval
            return launched


def atomic_json(path: Path, value: dict) -> None:
    """Replace a private receipt atomically."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    with temporary.open("x") as stream:
        temporary.chmod(0o600)
        json.dump(value, stream)
        stream.write("\n")
    temporary.replace(path)


def descendants(parent: int) -> dict[int, str]:
    """Capture Linux child identities without signaling the shared parent session."""
    processes = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
            processes[int(directory.name)] = (int(fields[1]), fields[19])
        except (OSError, ValueError, IndexError):
            continue
    owned = {parent}
    while True:
        children = {pid for pid, (ppid, _) in processes.items() if ppid in owned}
        if children <= owned:
            break
        owned.update(children)
    return {pid: processes[pid][1] for pid in owned - {parent}}


def signal_descendants(owned: dict[int, str], sig: int) -> None:
    """Signal only captured child PIDs whose kernel start identity still matches."""
    for pid, identity in owned.items():
        try:
            fields = (
                Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()
            )
            if fields[19] == identity:
                os.kill(pid, sig)
        except (OSError, ValueError, IndexError):
            continue


def terminate(process: subprocess.Popen, group: bool = True) -> None:
    """Terminate owned workers even when nested execution shares a pacing session."""
    owned = descendants(process.pid) if not group else {}
    for sig in (signal.SIGTERM, signal.SIGKILL):
        with contextlib.suppress(ProcessLookupError):
            if group:
                os.killpg(process.pid, sig)
            else:
                signal_descendants(owned, sig)
                process.send_signal(sig)
        if sig == signal.SIGTERM:
            time.sleep(0.2)
    process.wait()
