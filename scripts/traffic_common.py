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


def terminate(process: subprocess.Popen) -> None:
    """Terminate an entire scenario session, including background workers."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, sig)
        if sig == signal.SIGTERM:
            time.sleep(0.2)
    process.wait()
