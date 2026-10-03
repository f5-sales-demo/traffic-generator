"""A blocked public login cannot erase authenticated DVWA payload launches."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_each_dvwa_scenario_uses_real_origin_session_when_installed():
    for source in (ROOT / "suites/dvwa-exploits").glob("[0-9]*.sh"):
        text = source.read_text()
        assert (
            "dvwa-csrf-session"
            if source.name == "03-csrf-password-change.sh"
            else "dvwa-session"
        ) in text, source.name
        assert "TGEN_FIXTURES" in text, source.name
