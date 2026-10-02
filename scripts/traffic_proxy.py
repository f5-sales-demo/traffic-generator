"""Mitmproxy addon: one aggregate clock for scanners, browsers, and filler attacks."""

import asyncio
import json
import os
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from mitmproxy import http


class Budget:
    """One nonbursting launch clock for all intercepted HTTP connections."""

    def __init__(self) -> None:
        """Initialize the shared queue and private counters."""
        self.pending: asyncio.Queue = asyncio.Queue()
        self.domains = json.loads(os.environ["TGEN_DOMAINS"])
        self.metrics_path = Path(os.environ["TGEN_PROXY_METRICS"])
        self.counts: dict[str, Any] = {
            "attack_requests": 0,
            "scenario_requests": 0,
            "filler_requests": 0,
            "attack_transport_failures": 0,
            "scenario_transport_failures": 0,
            "tool_cancellations": 0,
            "attack_mitigated": 0,
            "denied_destinations": 0,
            "per_domain": {},
        }
        self.started = time.time()
        self.ticker: asyncio.Task | None = None
        self.tasks: set[asyncio.Task] = set()
        self.maximum_pending_fillers = 200
        self.scenario_file = self.metrics_path.parent / "current-scenario.json"

    def running(self) -> None:
        """Start one pacing clock; unused scenario slots rotate bounded synthetic attacks."""
        self.ticker = asyncio.create_task(self.tick())

    def done(self) -> None:
        """Stop every pending launch on proxy shutdown."""
        if self.ticker:
            self.ticker.cancel()
        for task in self.tasks:
            task.cancel()

    def count(self, host: str, filler: bool) -> None:
        """Count actual request dispatches, not tool process starts."""
        self.counts["attack_requests"] += 1
        self.counts["filler_requests" if filler else "scenario_requests"] += 1
        self.counts["per_domain"][host] = self.counts["per_domain"].get(host, 0) + 1
        self.persist()

    async def tick(self) -> None:
        """Dispatch exactly one request per slot, without accumulating idle burst credit."""
        next_slot = time.monotonic()
        while True:
            await asyncio.sleep(max(0, next_slot - time.monotonic()))
            next_slot = time.monotonic() + 0.05
            try:
                event, host = self.pending.get_nowait()
            except asyncio.QueueEmpty:
                if len(self.tasks) >= self.maximum_pending_fillers:
                    continue
                host = self.domains[self.counts["attack_requests"] % len(self.domains)]
                task = asyncio.create_task(asyncio.to_thread(self.filler, host))
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
                self.count(host, filler=True)
            else:
                self.count(host, filler=False)
                event.set()

    def filler(self, host: str) -> None:
        """Use spare attack slots for an explicitly identified harmless SQLi simulation."""
        opener = build_opener(
            ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context())
        )
        request = Request(
            "https://" + host + "/httpbin/get?tgen_synthetic=%27%20OR%201%3D1--",
            headers={
                "X-TGen-Class": "attack-filler",
                "X-MUD-User": "waap-synthetic-filler",
            },
        )
        try:
            with opener.open(request, timeout=10) as response:
                response.read()
        except HTTPError as error:
            if error.code in (403, 429):
                self.counts["attack_mitigated"] += 1
        except (URLError, OSError):
            self.counts["attack_transport_failures"] += 1

    def current_scenario(self) -> str:
        """Join requests to the supervised active scenario with a bounded synthetic identity."""
        try:
            identifier = json.loads(self.scenario_file.read_text())["id"]
            return identifier.replace("/", "-")
        except (OSError, KeyError, ValueError):
            return "catalog"

    async def request(self, flow: http.HTTPFlow) -> None:
        """All tool/browser descendants queue here immediately before upstream forwarding."""
        host = (
            (
                flow.request.headers.get("Host")
                or flow.client_conn.sni
                or flow.request.host
            )
            .split(":", 1)[0]
            .lower()
        )
        if host not in self.domains or flow.request.port not in (80, 443):
            self.counts["denied_destinations"] += 1
            flow.response = http.Response.make(
                470, b"Destination outside traffic allowlist"
            )
            self.persist()
            return
        flow.request.host = host
        if "X-MUD-User" not in flow.request.headers:
            flow.request.headers["X-MUD-User"] = (
                "waap-scenario-" + self.current_scenario() + "-" + host
            )
        event = asyncio.Event()
        await self.pending.put((event, host))
        await event.wait()

    def response(self, flow: http.HTTPFlow) -> None:
        """Mitigation is an HTTP outcome, separate from transport failure."""
        if flow.response.status_code in (403, 429):
            self.counts["attack_mitigated"] += 1
        self.persist()

    def error(self, flow: http.HTTPFlow) -> None:
        """Record failed proxied upstream requests."""
        if flow.error and any(
            word in flow.error.msg.lower()
            for word in (
                "client",
                "killed",
                "cancel",
                "disconnected",
                "connection closed",
            )
        ):
            self.counts["tool_cancellations"] += 1
        else:
            self.counts["scenario_transport_failures"] += 1
        self.persist()

    def persist(self) -> None:
        """Private atomic metrics contain no payloads or account credentials."""
        temporary = self.metrics_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({**self.counts, "started": self.started, "updated": time.time()})
        )
        temporary.chmod(0o600)
        temporary.replace(self.metrics_path)


addons = [Budget()]
