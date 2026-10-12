"""Filler denials drain and close real response streams; errors remain failures."""

import importlib.util
import io
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError


def proxy_module(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_DOMAINS", '["www.example.test"]')
    monkeypatch.setenv("TGEN_PROXY_METRICS", str(tmp_path / "metrics.json"))
    spec = importlib.util.spec_from_file_location(
        "filler_response_proxy", Path(__file__).parents[1] / "scripts/traffic_proxy.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_filler_native_denial_closes_stream_after_read(tmp_path, monkeypatch):
    module = proxy_module(tmp_path, monkeypatch)
    budget = module.Budget()
    stream = io.BytesIO(b"native-denial")
    error = HTTPError(
        "https://www.example.test/httpbin/get", 403, "denied", Message(), stream
    )
    with patch.object(module, "build_opener") as opener:
        opener.return_value.open.side_effect = error
        budget.filler("www.example.test")
    assert stream.closed
    assert budget.counts["attack_mitigated"] == 1
    assert budget.counts["attack_transport_failures"] == 0
    budget.done()


def test_filler_transport_failure_keeps_bounded_category(tmp_path, monkeypatch):
    module = proxy_module(tmp_path, monkeypatch)
    budget = module.Budget()
    with patch.object(module, "build_opener") as opener:
        opener.return_value.open.side_effect = URLError(TimeoutError("private detail"))
        budget.filler("www.example.test")
    assert budget.counts["attack_transport_failures"] == 1
    assert budget.counts["error_categories"] == {"filler:TimeoutError": 1}
    assert budget.counts["attack_mitigated"] == 0
    budget.done()
