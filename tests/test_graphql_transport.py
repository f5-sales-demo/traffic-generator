"""GraphQL helper arguments become valid JSON without shell reinterpretation."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_graphql_helper_preserves_query_quotes_and_variables():
    """Quoted GraphQL strings remain intact at the request transport boundary."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        curl = root / "curl"
        curl.write_text(
            "#!/usr/bin/env python3\nimport json,sys\narguments=sys.argv[1:]\nprint(arguments[arguments.index('-d')+1])\n"
        )
        curl.chmod(0o755)
        environment = dict(os.environ, PATH=temporary + ":" + os.environ["PATH"])
        query = 'mutation{createPaste(title:"synthetic \\"quoted\\"",content:"fixture"){paste{id}}}'
        command = [
            "bash",
            "-c",
            'source "$1"; gql_query "$2" "$3"',
            "bash",
            str(ROOT / "suites/dvga-exploits/_dvga-lib.sh"),
            query,
            '{"fixture":"synthetic"}',
        ]
        result = subprocess.run(  # noqa: S603 - owned GraphQL helper with synthetic argv
            command,
            env=dict(environment, TARGET_FQDN="www.example.test"),
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(result.stdout) == {
            "query": query,
            "variables": {"fixture": "synthetic"},
        }
