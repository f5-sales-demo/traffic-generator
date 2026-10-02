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

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_scanner_and_browser_requests_share_actual_clock(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"TGEN_DOMAINS": '["www.example.test","api.example.test"]', "TGEN_PROXY_METRICS": tmp + "/metrics.json"}):
            spec = importlib.util.spec_from_file_location("traffic_proxy_test", ROOT / "scripts/traffic_proxy.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            budget = module.Budget()
            dispatched = []
            async def request(index):
                flow = SimpleNamespace(request=SimpleNamespace(headers={"Host": "www.example.test"}, host="192.0.2.1", port=443))
                await budget.request(flow)
                dispatched.append(time.monotonic())
            pending = [asyncio.create_task(request(i)) for i in range(21)]
            await asyncio.sleep(0)
            budget.running()
            await asyncio.gather(*pending)
            budget.done()
            self.assertGreaterEqual(dispatched[-1] - dispatched[0], 0.99)
            self.assertEqual(budget.counts["scenario_requests"], 21)
            self.assertEqual(budget.counts["filler_requests"], 0)
            escaped = SimpleNamespace(request=SimpleNamespace(headers={"Host": "outside.example.test"}, port=443))
            await budget.request(escaped)
            self.assertEqual(escaped.response.status_code, 470)
            self.assertEqual(budget.counts["denied_destinations"], 1)
            self.assertEqual(json.loads(pathlib.Path(tmp + "/metrics.json").read_text())["attack_requests"], 21)


if __name__ == "__main__":
    unittest.main()
