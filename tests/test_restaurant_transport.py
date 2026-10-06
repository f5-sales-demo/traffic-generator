"""Command payload metacharacters must be transported as one query parameter."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_command_injection_encodes_parameters_without_splitting_ampersands():
    for name in ["07-command-injection.sh", "08-full-escalation-chain.sh"]:
        source = (ROOT / "suites/restaurant-exploits" / name).read_text()
        assert "--data-urlencode" in source
        assert "disk?parameters=${PAYLOAD}" not in source
