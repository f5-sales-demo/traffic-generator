"""Accept exact host-journaled native family restoration only."""

import json
from pathlib import Path

REPLICA_COUNT = 4


def family_restored(result: dict, directory: Path) -> bool:
    """All four replica baselines and source-bound journal IDs must match after recovery."""
    try:
        before = json.loads((directory / "family-baseline.json").read_text())
        after = json.loads((directory / "family-restoration.json").read_text())
        return (
            after.get("restored") is True
            and before.get("identity") == after.get("identity")
            and before.get("family") == after.get("family")
            and before.get("marker") == after.get("marker")
            and after.get("after") == before.get("replicas")
            and len(after.get("after", {}))
            == (REPLICA_COUNT * 5 if before.get("family") == "mixed" else REPLICA_COUNT)
            and all(
                after.get(key) == before.get(key) == result.get(key)
                for key in ["source_commit", "artifact_sha256"]
            )
        )
    except (OSError, ValueError, KeyError):
        return False
