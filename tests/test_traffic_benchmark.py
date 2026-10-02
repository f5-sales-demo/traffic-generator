"""Benchmark keepalive uses real reusable connections and closes them."""

import importlib.util
import json
import os
import pathlib
import tempfile
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "benchmark", ROOT / "scripts/traffic_benchmark.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_keepalive_reuses_connections_and_records_cleanup():
    with (
        tempfile.TemporaryDirectory() as tmp,
        patch.dict(
            os.environ,
            {
                "TGEN_AUTHORIZED_HOST": "www.example.test",
                "TGEN_CONCURRENCY": "1",
                "TGEN_REQUESTS": "4",
                "TGEN_RESULTS_DIR": tmp,
            },
        ),
        patch("sys.argv", ["benchmark", "bench-keepalive", "www.example.test"]),
        patch.object(module.http.client, "HTTPSConnection") as connection,
    ):
        connection.return_value.getresponse.return_value.status = 200
        assert module.main() == 0
        assert connection.call_count == 1
        assert connection.return_value.request.call_count == 4
        connection.return_value.close.assert_called()
        receipt = json.loads(pathlib.Path(tmp, "benchmark.json").read_text())
        assert receipt["connections_created"] == 1
