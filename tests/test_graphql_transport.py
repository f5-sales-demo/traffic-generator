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


def test_complete_depth_sequence_bounds_root_list_and_preserves_schema(tmp_path):
    curl = tmp_path / "curl"
    capture = tmp_path / "queries.jsonl"
    curl.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\na=sys.argv[1:];q=json.loads(a[a.index('-d')+1]);open(os.environ['QUERY_CAPTURE'],'a').write(json.dumps(q)+'\\n');print(json.dumps({'data':{'pastes':[{'title':'synthetic','owner':{'name':'synthetic'}}]}}))\n"
    )
    curl.chmod(0o755)
    subprocess.run(  # noqa: S603 - exact owned script and synthetic recording transport
        [
            "/bin/bash",
            str(ROOT / "suites/dvga-exploits/02-deep-recursion.sh"),
            "www.example.test",
        ],
        env=dict(
            os.environ,
            PATH=str(tmp_path) + ":" + os.environ["PATH"],
            QUERY_CAPTURE=str(capture),
        ),
        capture_output=True,
        text=True,
        check=True,
    )
    queries = [json.loads(line)["query"] for line in capture.read_text().splitlines()]
    assert len(queries) == 10
    assert all(
        q.startswith("{pastes(limit:1){") and q.count("limit:1") == 1 for q in queries
    )
    assert [q.count("owner{") for q in queries] == [0, 1, 1, 2, 2, 3, 3, 4, 4, 5]
