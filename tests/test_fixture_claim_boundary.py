"""Seeded post-mitigation credentials cannot be represented as successful escalation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_chain_labels_seeded_chef_as_fixture_not_exploit_success():
    source = (
        ROOT / "suites/restaurant-exploits/08-full-escalation-chain.sh"
    ).read_text()
    assert "CHEF_TOKEN_FROM_FIXTURE=true" in source
    assert "Seeded Chef token does not prove role escalation" in source
