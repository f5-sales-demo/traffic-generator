"""Native family recovery cannot pass with missing replicas or stale provenance."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from traffic_family_functional import family_restored


def test_family_recovery_requires_exact_four_replica_baselines(tmp_path):
    result = {"source_commit": "a" * 40, "artifact_sha256": "b" * 64}
    replicas = {"vampi-" + str(i): {"users": [], "books": []} for i in range(1, 5)}
    before = {**result, "identity": "c" * 32, "replicas": replicas}
    after = {**before, "restored": True, "after": replicas}
    (tmp_path / "family-baseline.json").write_text(json.dumps(before))
    path = tmp_path / "family-restoration.json"
    path.write_text(json.dumps(after))
    assert family_restored(result, tmp_path)
    after["after"] = {"vampi-1": replicas["vampi-1"]}
    path.write_text(json.dumps(after))
    assert not family_restored(result, tmp_path)
    after["after"] = replicas
    after["source_commit"] = "d" * 40
    path.write_text(json.dumps(after))
    assert not family_restored(result, tmp_path)
