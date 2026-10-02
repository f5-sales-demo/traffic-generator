"""Two synthetic accounts remain distinct despite a mitigated registration prerequisite."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FixtureTests(unittest.TestCase):
    def test_seeded_fixture_selection_alternates_and_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            fixtures = directory / "fixtures.json"
            fixtures.write_text(
                json.dumps(
                    {
                        "crapi_tokens": [
                            "synthetic-real-token-a",
                            "synthetic-real-token-b",
                        ]
                    }
                )
            )
            fixtures.chmod(0o600)
            environment = dict(
                os.environ, TGEN_FIXTURES=str(fixtures), TGEN_RESULTS_DIR=tmp
            )
            tokens = []
            for _ in range(3):
                result = subprocess.run(  # noqa: S603 - fixed regression command
                    [
                        sys.executable,
                        str(ROOT / "scripts/traffic_fixtures.py"),
                        "crapi-token",
                    ],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                tokens.append(result.stdout.strip())
            assert tokens == [
                "synthetic-real-token-a",
                "synthetic-real-token-b",
                "synthetic-real-token-a",
            ]
            fixtures.chmod(0o644)
            result = subprocess.run(  # noqa: S603 - fixed regression command
                [
                    sys.executable,
                    str(ROOT / "scripts/traffic_fixtures.py"),
                    "crapi-token",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode != 0


if __name__ == "__main__":
    unittest.main()
