"""Resolve opaque child markers only inside the owned runtime receipt tree."""

import json
import re
from pathlib import Path


def child_metadata(runtime: Path, marker: str, parent: dict) -> dict:
    """Foreign or invalid attribution cannot redirect receipt writes."""
    if not re.fullmatch(r"[a-z0-9-]{1,80}", marker):
        return parent
    path = runtime / "children" / (marker + ".json")
    try:
        child = json.loads(path.read_text())
        valid = Path(child["dispatch_path"]).resolve().is_relative_to(runtime.resolve())
    except (OSError, ValueError, KeyError):
        child, valid = parent, False
    return child if valid else parent
