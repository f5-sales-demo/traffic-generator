"""Actual shared dispatch-clock and destination safety contracts."""

import asyncio
import importlib.util
import json
import os
import pathlib
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


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
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            dispatched = []

            async def request(index):
                flow = SimpleNamespace(
                    metadata={},
                    request=SimpleNamespace(
                        headers={"Host": "www.example.test"}, host="192.0.2.1", port=443
                    ),
                )
                await budget.request(flow)
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
                    headers={"Host": "outside.example.test"}, port=443
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


if __name__ == "__main__":
    unittest.main()
