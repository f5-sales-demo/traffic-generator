"""RESTaurant roles come from native profiles; temporary actors require journals."""

import json
from pathlib import Path


def test_role_readback_and_command_jwt_actor_journals():
    root = Path(__file__).resolve().parents[1]
    catalog = json.loads((root / "suites/catalog.json").read_text())
    for name in ("07-command-injection.sh", "08-full-escalation-chain.sh"):
        source = (root / "suites/restaurant-exploits" / name).read_text()
        assert '/profile" -H "$(auth_header "$CHEF_TOKEN")"' in source
        assert "json.load(sys.stdin).get('role','unknown')" in source
    for identifier in (
        "restaurant-exploits/07-command-injection",
        "restaurant-exploits/09-jwt-secret-crack",
    ):
        row = next(r for r in catalog["scenarios"] if r["id"] == identifier)
        assert row["launch"] == "scripts/traffic_family_native.py"
        assert row["fixture_contract"]["family_restore"] == "restaurant"
        assert row["functional_contract"]["mutation_policy"] == "journaled-restoration"
