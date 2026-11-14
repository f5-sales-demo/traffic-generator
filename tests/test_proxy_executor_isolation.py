"""Blocking filler I/O must not queue proxy upstream DNS behind attack work."""

import asyncio
import importlib.util
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def test_blocked_filler_keeps_real_loop_dns_available(tmp_path, monkeypatch):
    monkeypatch.setenv("TGEN_DOMAINS", '["www.example.test"]')
    monkeypatch.setenv("TGEN_PROXY_METRICS", str(tmp_path / "metrics.json"))
    spec = importlib.util.spec_from_file_location(
        "executor_isolation_proxy",
        Path(__file__).parents[1] / "scripts/traffic_proxy.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    entered = threading.Event()
    release = threading.Event()

    def blocked_filler(_host):
        entered.set()
        release.wait(2)

    async def exercise():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        budget = module.Budget()
        monkeypatch.setattr(budget, "filler", blocked_filler)
        budget.running()
        try:
            deadline = time.monotonic() + 1
            while not entered.is_set():
                assert time.monotonic() < deadline
                await asyncio.sleep(0.01)
            addresses = await asyncio.wait_for(loop.getaddrinfo("localhost", 443), 0.2)
            assert addresses
            assert budget.counts["attack_requests"] >= 1
        finally:
            release.set()
            budget.done()
            await asyncio.sleep(0.05)

    asyncio.run(exercise())
