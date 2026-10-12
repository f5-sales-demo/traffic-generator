"""Native child setup must match its declared tool and mutation contracts."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_mutating_restaurant_children_have_journal_adapter():
    scenarios = json.loads((ROOT / "suites/catalog.json").read_text())["scenarios"]
    for identifier in (
        "restaurant-exploits/07-command-injection",
        "restaurant-exploits/09-jwt-secret-crack",
    ):
        scenario = next(row for row in scenarios if row["id"] == identifier)
        assert scenario["adapter"] == "native-family-journal"
        assert scenario["fixture_contract"]["family_restore"] == "restaurant"
        assert (
            scenario["functional_contract"]["mutation_policy"]
            == "journaled-restoration"
        )


def test_dalfox_v3_uses_required_target_option_for_both_native_scans():
    source = (ROOT / "suites/web-app-attacks/02-xss.sh").read_text()
    assert source.count('dalfox url --url "${BASE}') == 2
    assert "--silence --no-color --timeout 10" in source
