"""Native signup never substitutes a seeded actor or skips exact recovery."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import crapi_signup_fixture as signup


def test_journal_is_written_before_signup(tmp_path):
    signup.Signup("https://www.example.test/crapi", tmp_path)
    assert json.loads((tmp_path / "fixture-journal.json").read_text())[
        "email"
    ].startswith("signup-")
    assert (tmp_path / "fixture-journal.json").stat().st_mode & 0o777 == 0o600


def test_failure_runs_exact_recovery_and_does_not_pass(tmp_path):
    with (
        patch.dict(
            os.environ,
            {
                "TGEN_AUTHORIZED_HOST": "www.example.test",
                "TGEN_RESULTS_DIR": str(tmp_path),
                "SOURCE_COMMIT": "a" * 40,
                "TGEN_ARTIFACT_SHA256": "b" * 64,
            },
        ),
        patch.object(
            signup.Signup, "execute", side_effect=ValueError("native failure")
        ),
        patch.object(signup, "recover", return_value={"passed": True}) as recover,
    ):
        assert signup.main() == 1
        recover.assert_called_once_with(tmp_path)
        assert (
            json.loads((tmp_path / "signup-functional.json").read_text())["passed"]
            is False
        )
