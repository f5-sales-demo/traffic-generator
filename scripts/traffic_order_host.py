"""Run only declared order journal jobs outside the HTTP egress namespace."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import threading
    from pathlib import Path

from traffic_common import atomic_json


def host_jobs(root: Path, runtime: Path, config: dict, stop: threading.Event) -> None:
    """Process task-owned nested order requests with fixed helper argv and source binding."""
    while not stop.wait(0.5):
        for file in runtime.glob("pass-*/**/order-host-request.json"):
            if file.is_symlink():
                continue
            response = file.with_name("order-host-response.json")
            if response.exists():
                continue
            request = json.loads(file.read_text())
            if (
                request.get("action") not in ("prepare", "restore")
                or request.get("source_commit") != config["source_commit"]
                or request.get("artifact_sha256") != config["artifact_sha256"]
            ):
                atomic_json(response, {"passed": False, "request": request})
                continue
            environment = dict(
                os.environ,
                TGEN_FIXTURES=str(runtime.parent / "fixtures.json"),
                SOURCE_COMMIT=config["source_commit"],
                TGEN_ARTIFACT_SHA256=config["artifact_sha256"],
            )
            result = subprocess.run(  # noqa: S603 - fixed recovery helper outside HTTP namespace
                [
                    sys.executable,
                    "-B",
                    str(root / "scripts/crapi_order_fixture.py"),
                    request["action"],
                    str(file.parent),
                ],
                env=environment,
                capture_output=True,
                check=False,
                timeout=90,
            )
            atomic_json(
                response, {"passed": result.returncode == 0, "request": request}
            )


def restore_receipt(directory: Path) -> bool:
    """Nested acceptance requires the host restoration receipt after job completion."""
    path = directory / "order-restoration.json"
    return path.is_file() and json.loads(path.read_text()).get("restored") is True
