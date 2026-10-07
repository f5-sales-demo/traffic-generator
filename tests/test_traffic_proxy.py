"""Actual shared dispatch-clock and destination safety contracts."""

import asyncio
import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_scanner_and_browser_requests_share_actual_clock(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(
                os.environ,
                {
                    "TGEN_DOMAINS": '["www.example.test","api.example.test"]',
                    "TGEN_PROXY_METRICS": tmp + "/metrics.json",
                },
            ),
        ):
            spec = importlib.util.spec_from_file_location(
                "traffic_proxy_test", ROOT / "scripts/traffic_proxy.py"
            )
            assert spec is not None
            assert spec.loader is not None
            assert spec is not None
            assert spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            dispatched = []

            async def request(_index):
                flow = SimpleNamespace(
                    metadata={},
                    request=SimpleNamespace(
                        content=b"synthetic",
                        headers={"Host": "www.example.test"},
                        host="192.0.2.1",
                        port=443,
                        method="GET",
                        path="/httpbin/get",
                    ),
                )
                await budget.request(flow)
                assert re.fullmatch(
                    r"showcase-[0-9a-f]{32}-[a-z0-9-]+",
                    flow.request.headers["X-MUD-User"],
                )
                dispatched.append(time.monotonic())

            pending = [asyncio.create_task(request(i)) for i in range(21)]
            await asyncio.sleep(0)
            budget.running()
            await asyncio.gather(*pending)
            budget.done()
            assert dispatched[-1] - dispatched[0] >= 0.99
            assert budget.counts["scenario_requests"] == 21
            assert budget.counts["filler_requests"] == 0
            escaped = SimpleNamespace(
                request=SimpleNamespace(
                    content=b"synthetic",
                    headers={"Host": "outside.example.test"},
                    port=443,
                )
            )
            await budget.request(escaped)
            assert escaped.response.status_code == 470
            assert budget.counts["denied_destinations"] == 1
            assert (
                json.loads(pathlib.Path(tmp + "/metrics.json").read_text())[
                    "attack_requests"
                ]
                == 21
            )

    async def test_dispatch_keeps_phase_and_contract_from_enqueue(self):
        """Changing active phases cannot reattribute an already queued request."""
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(
                os.environ,
                {
                    "TGEN_DOMAINS": '["www.example.test","api.example.test"]',
                    "TGEN_PROXY_METRICS": temporary + "/metrics.json",
                },
            ),
        ):
            spec = importlib.util.spec_from_file_location(
                "phase_proxy", ROOT / "scripts/traffic_proxy.py"
            )
            assert spec is not None
            assert spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            evidence = pathlib.Path(temporary) / "scenario-events.jsonl"
            current = {
                "id": "synthetic/action",
                "phase": "prerequisite",
                "dispatch_path": str(evidence),
                "dispatch_contract": {
                    "requirements": [
                        {
                            "id": "action",
                            "method": "POST",
                            "path": "/httpbin/post",
                            "body_exact": "synthetic",
                            "payload_class": "fixture",
                            "minimum_dispatches": 1,
                        }
                    ]
                },
            }
            budget.scenario_file.write_text(json.dumps(current))
            flow = SimpleNamespace(
                metadata={},
                request=SimpleNamespace(
                    content=b"synthetic",
                    headers={"Host": "www.example.test"},
                    host="www.example.test",
                    port=443,
                    method="POST",
                    path="/httpbin/post",
                    get_text=lambda **_options: "synthetic",
                ),
            )
            pending = asyncio.create_task(budget.request(flow))
            await asyncio.sleep(0)
            current["phase"] = "execution"
            budget.scenario_file.write_text(json.dumps(current))
            budget.maximum_pending_fillers = 0
            budget.running()
            await pending
            budget.done()
            event = json.loads(evidence.read_text())
            assert event["kind"] == "prerequisite"
            assert event["matched_requirements"] == []
            assert "body" not in event
            assert "headers" not in event

    async def test_cancelled_requests_do_not_consume_dispatches(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(
                os.environ,
                {
                    "TGEN_DOMAINS": '["www.example.test","api.example.test"]',
                    "TGEN_PROXY_METRICS": tmp + "/metrics.json",
                },
            ),
        ):
            spec = importlib.util.spec_from_file_location(
                "cancel_proxy", ROOT / "scripts/traffic_proxy.py"
            )
            assert spec is not None
            assert spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            flow = SimpleNamespace(
                metadata={},
                request=SimpleNamespace(headers={"Host": "www.example.test"}, port=443),
            )
            pending = asyncio.create_task(budget.request(flow))
            await asyncio.sleep(0)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            budget.maximum_pending_fillers = 0
            budget.running()
            await asyncio.sleep(0.12)
            budget.done()
            assert budget.counts["scenario_requests"] == 0

    async def test_disconnect_cancels_queued_slot(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(
                os.environ,
                {
                    "TGEN_DOMAINS": '["www.example.test","api.example.test"]',
                    "TGEN_PROXY_METRICS": tmp + "/metrics.json",
                },
            ),
        ):
            spec = importlib.util.spec_from_file_location(
                "disconnect_proxy", ROOT / "scripts/traffic_proxy.py"
            )
            assert spec is not None
            assert spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            future = asyncio.get_running_loop().create_future()
            flow = SimpleNamespace(
                metadata={"tgen_pending_slot": future},
                error=SimpleNamespace(msg="client disconnected"),
                request=SimpleNamespace(method="GET", path="/synthetic"),
            )
            budget.error(flow)
            assert future.cancelled()
            assert budget.counts["tool_cancellations"] == 1

    async def test_raw_connect_receipt_records_forwarded_method(self):
        """The carrier GET is not the intended CONNECT dispatch."""
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(
                os.environ,
                {
                    "TGEN_DOMAINS": '["www.example.test","api.example.test"]',
                    "TGEN_PROXY_METRICS": tmp + "/metrics.json",
                },
            ),
        ):
            spec = importlib.util.spec_from_file_location(
                "raw_proxy", ROOT / "scripts/traffic_proxy.py"
            )
            assert spec is not None
            assert spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            evidence = pathlib.Path(tmp) / "dispatch-events.jsonl"
            budget.scenario_file.write_text(
                json.dumps(
                    {
                        "id": "synthetic/connect",
                        "phase": "execution",
                        "dispatch_path": str(evidence),
                        "dispatch_contract": {
                            "requirements": [
                                {
                                    "id": "connect",
                                    "method": "CONNECT",
                                    "path": "/httpbin/get",
                                    "payload_class": "method-probe",
                                    "minimum_dispatches": 1,
                                }
                            ]
                        },
                    }
                )
            )
            flow = SimpleNamespace(
                metadata={},
                request=SimpleNamespace(
                    content=b"",
                    headers={
                        "Host": "www.example.test",
                        "X-TGen-Raw-Method": "CONNECT",
                    },
                    host="www.example.test",
                    port=443,
                    method="GET",
                    path="/httpbin/get",
                    get_text=lambda **_: "",
                ),
            )
            with patch.object(
                budget,
                "raw_connect",
                return_value=module.http.Response.make(403, b"blocked"),
            ):
                pending = asyncio.create_task(budget.request(flow))
                await asyncio.sleep(0)
                budget.maximum_pending_fillers = 0
                budget.running()
                await pending
                budget.done()
            event = json.loads(evidence.read_text())
            assert event["method"] == "CONNECT"
            assert event["matched_requirements"] == ["connect"]
            assert flow.metadata["tgen_dispatched_method"] == "CONNECT"

    async def test_response_records_actual_request_join_fields_without_credentials(
        self,
    ):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(
                os.environ,
                {
                    "TGEN_DOMAINS": '["www.example.test","api.example.test"]',
                    "TGEN_PROXY_METRICS": tmp + "/metrics.json",
                },
            ),
        ):
            spec = importlib.util.spec_from_file_location(
                "join_proxy", ROOT / "scripts/traffic_proxy.py"
            )
            assert spec is not None
            assert spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            identity = "showcase-" + "a" * 32 + "-rapid-ua-0"
            evidence = pathlib.Path(tmp) / "dispatch-events.jsonl"
            budget.scenario_file.write_text(
                json.dumps(
                    {
                        "id": "synthetic/action",
                        "phase": "execution",
                        "dispatch_path": str(evidence),
                        "dispatch_contract": {
                            "requirements": [
                                {
                                    "id": "read",
                                    "method": "GET",
                                    "path": "/httpbin/get",
                                    "payload_class": "synthetic",
                                    "minimum_dispatches": 1,
                                }
                            ]
                        },
                    }
                )
            )
            flow = SimpleNamespace(
                metadata={},
                request=SimpleNamespace(
                    content=b"synthetic",
                    headers={
                        "Host": "www.example.test",
                        "X-MUD-User": identity,
                        "Authorization": "Bearer private-token",
                    },
                    host="www.example.test",
                    port=443,
                    method="GET",
                    path="/httpbin/get?q=synthetic",
                    get_text=lambda **_: "synthetic",
                ),
            )
            pending = asyncio.create_task(budget.request(flow))
            await asyncio.sleep(0)
            budget.maximum_pending_fillers = 0
            budget.running()
            await pending
            budget.done()
            flow.response = module.http.Response.make(
                200,
                b'{"url":"https://www.example.test/httpbin/get","headers":{}}',
                {"content-type": "application/json"},
            )
            budget.record_outcome(flow, status=200)
            event = json.loads(evidence.with_name("response-events.jsonl").read_text())
            assert event["domain"] == "www.example.test"
            assert event["synthetic_identity"] == identity
            assert event["sent_at"] <= event["received_at"]
            assert len(event["payload_sha256"]) == 64
            assert len(event["response_sha256"]) == 64
            assert "private-token" not in json.dumps(event)
            assert "headers" not in event


if __name__ == "__main__":
    unittest.main()


def test_juice_journal_marker_is_injected_from_owned_baseline(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_DOMAINS", '["www.example.test"]')
    monkeypatch.setenv("TGEN_PROXY_METRICS", str(tmp_path / "metrics.json"))
    spec = importlib.util.spec_from_file_location(
        "juice_proxy", ROOT / "scripts/traffic_proxy.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    budget = module.Budget()
    marker = "tgen-" + "a" * 32
    (tmp_path / "family-baseline.json").write_text(json.dumps({"marker": marker}))
    budget.scenario_file.write_text(
        json.dumps(
            {
                "id": "synthetic/juice",
                "phase": "execution",
                "dispatch_path": str(tmp_path / "events.jsonl"),
                "fixture_contract": {"family_restore": "juice-shop"},
            }
        )
    )
    flow = SimpleNamespace(
        metadata={},
        request=SimpleNamespace(
            content=b"{}",
            headers={"Host": "www.example.test", "X-TGen-Family": "foreign"},
            host="www.example.test",
            port=443,
            method="GET",
            path="/juice-shop/api/Products",
            get_text=lambda **_options: "{}",
        ),
    )

    async def exercise():
        pending = asyncio.create_task(budget.request(flow))
        await asyncio.sleep(0)
        budget.running()
        await pending
        budget.done()

    asyncio.run(exercise())
    assert flow.request.headers["X-TGen-Family"] == marker
