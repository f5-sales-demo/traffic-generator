"""Request source-bound signup recovery from the existing owning-host worker."""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import TYPE_CHECKING

from traffic_common import atomic_json

if TYPE_CHECKING:
    from pathlib import Path


def host_action(directory: Path) -> None:
    """Wait for exact native signup cleanup without exposing host credentials."""
    request = {
        "action": "restore",
        "identity": uuid.uuid4().hex,
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
    }
    response = directory / "signup-host-response.json"
    response.unlink(missing_ok=True)
    atomic_json(directory / "signup-host-request.json", request)
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        if response.exists():
            receipt = json.loads(response.read_text())
            if receipt.get("request") == request and receipt.get("passed") is True:
                return
            message = "native signup host recovery failed"
            raise ValueError(message)
        time.sleep(0.5)
    message = "signup host recovery deadline exceeded"
    raise ValueError(message)
