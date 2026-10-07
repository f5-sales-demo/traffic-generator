"""Mitmproxy addon: one aggregate clock for scanners, browsers, and filler attacks."""

import asyncio
import contextlib
import hashlib
import http.client as http_client
import json
import os
import re
import ssl
import time
import uuid
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from mitmproxy import http
from traffic_attribution import child_metadata
from traffic_dispatch import (
    classify_outcome,
    declared_socket_cleanup,
    match_requirements,
    response_content_matches,
)
from traffic_native_identity import native_identity

HTTPS_PORT = 443


class Budget:
    """One nonbursting launch clock for all intercepted HTTP connections."""

    def __init__(self) -> None:
        """Initialize the shared queue and private counters."""
        self.pending: asyncio.Queue = asyncio.Queue()
        self.domains = json.loads(os.environ["TGEN_DOMAINS"])
        self.metrics_path = Path(os.environ["TGEN_PROXY_METRICS"])
        self.counts: dict[str, Any] = {
            "run_identity": uuid.uuid4().hex,
            "attack_requests": 0,
            "scenario_requests": 0,
            "filler_requests": 0,
            "attack_transport_failures": 0,
            "scenario_transport_failures": 0,
            "tool_cancellations": 0,
            "browser_cleanup_cancellations": 0,
            "attack_mitigated": 0,
            "denied_destinations": 0,
            "error_categories": {},
            "per_domain": {},
        }
        self.tls_context = ssl.create_default_context()
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
            event = None
            while not self.pending.empty():
                candidate, host = self.pending.get_nowait()
                if not candidate.done():
                    event = candidate
                    break
            if event is None:
                if len(self.tasks) >= self.maximum_pending_fillers:
                    continue
                host = self.domains[self.counts["attack_requests"] % len(self.domains)]
                task = asyncio.create_task(asyncio.to_thread(self.filler, host))
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
                self.count(host, filler=True)
            else:
                self.count(host, filler=False)
                event.set_result(None)

    def filler(self, host: str) -> None:
        """Use spare attack slots for an explicitly identified harmless SQLi simulation."""
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=self.tls_context))
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

    def family_marker(self, flow: http.HTTPFlow, current: dict) -> None:
        """Bind native recovery headers to the host-captured scenario baseline."""
        if current.get("fixture_contract", {}).get("family_restore") == "juice-shop":
            baseline = Path(current["dispatch_path"]).parent / "family-baseline.json"
            family = json.loads(baseline.read_text())
            if not re.fullmatch(r"tgen-[a-f0-9]{32}", family.get("marker", "")):
                message = "invalid native family request marker"
                raise ValueError(message)
            flow.request.headers["X-TGen-Family"] = family["marker"]

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
        # Older scanners send cleartext HTTP to 443; the authorized origin listener requires TLS.
        flow.request.scheme = "https" if flow.request.port == HTTPS_PORT else "http"
        if "X-MUD-User" not in flow.request.headers:
            flow.request.headers["X-MUD-User"] = (
                "showcase-"
                + self.counts["run_identity"]
                + "-scenario-"
                + self.current_scenario()
                + "-"
                + host.replace(".", "-")
            )
        try:
            current = json.loads(self.scenario_file.read_text())
        except (OSError, ValueError):
            current = {"id": "catalog", "phase": "unattributed"}
        marker = flow.request.headers.pop("X-TGen-Child", "")
        if not marker:
            native_marker = re.search(
                r"(?:^| )TGen-Child/([a-z0-9-]{1,80})(?: |$)",
                flow.request.headers.get("User-Agent", ""),
            )
            if native_marker:
                marker = native_marker.group(1)
        if marker:
            current = child_metadata(self.metrics_path.parent, marker, current)
        worker_marker = flow.request.headers.pop("X-TGen-Worker", "")
        if worker_marker and not re.fullmatch(r"(?:wrk|hey|ab)-[0-9]+", worker_marker):
            message = "invalid native worker attribution"
            raise ValueError(message)
        flow.metadata["tgen_worker"] = worker_marker
        self.family_marker(flow, current)
        flow.metadata["tgen_scenario"] = current
        event = asyncio.get_running_loop().create_future()
        flow.metadata["tgen_pending_slot"] = event
        await self.pending.put((event, host))
        await event
        flow.metadata.pop("tgen_pending_slot", None)
        flow.metadata["tgen_upstream_dispatched"] = True
        flow.metadata["tgen_request_sent_at"] = time.time()
        flow.metadata["tgen_request_domain"] = host
        flow.metadata["tgen_synthetic_identity"] = flow.request.headers.get(
            "X-MUD-User", ""
        )
        flow.metadata["tgen_payload_sha256"] = hashlib.sha256(
            flow.request.content or b""
        ).hexdigest()
        try:
            current = flow.metadata["tgen_scenario"]
            event_path = Path(current["dispatch_path"])
            if not event_path.resolve().is_relative_to(
                self.metrics_path.parent.resolve()
            ):
                message = "dispatch receipt escaped the owned results directory"
                raise ValueError(message)
        except (OSError, KeyError):
            event_path = self.metrics_path.parent / "dispatch-events.jsonl"
        raw_method = flow.request.headers.pop("X-TGen-Raw-Method", "")
        dispatched_method = (
            "CONNECT" if raw_method == "CONNECT" else flow.request.method
        )
        flow.metadata["tgen_dispatched_method"] = dispatched_method
        observed = {
            "body_hex": (flow.request.content or b"").hex(),
            "kind": "scenario"
            if current.get("phase") == "execution"
            else "prerequisite",
            "method": flow.metadata.get("tgen_dispatched_method", flow.request.method),
            "path": flow.request.path.split("?", 1)[0],
            "query": flow.request.path.partition("?")[2],
            "body": flow.request.get_text(strict=False) or ""
            if hasattr(flow.request, "get_text")
            else "",
            "headers": {
                name.lower(): value for name, value in flow.request.headers.items()
            },
        }
        matched = match_requirements(current.get("dispatch_contract", {}), observed)
        flow.metadata["tgen_matched_requirements"] = matched
        with event_path.open("a", encoding="utf-8") as stream:
            event_path.chmod(0o600)
            # This private receipt records endpoint and payload class inputs, never headers/cookies.
            stream.write(
                json.dumps(
                    {
                        "worker_marker": flow.metadata.get("tgen_worker", ""),
                        "scenario": current.get("id"),
                        "kind": observed["kind"],
                        "matched_requirements": matched,
                        "method": flow.metadata.get(
                            "tgen_dispatched_method", flow.request.method
                        ),
                        "path": flow.request.path.split("?", 1)[0],
                        "query": flow.request.path.partition("?")[2],
                        "dispatched": time.time(),
                    }
                )
                + "\n"
            )
        if raw_method == "CONNECT":
            flow.response = await asyncio.to_thread(
                self.raw_connect, host, flow.request.path
            )

    def raw_connect(self, host: str, path: str) -> http.Response:
        """Forward an HTTP CONNECT method probe in its counted slot without opening a tunnel."""
        connection = http_client.HTTPSConnection(
            host, timeout=10, context=self.tls_context
        )
        try:
            connection.request(
                "CONNECT",
                path,
                headers={
                    "Host": host,
                    "X-MUD-User": "waap-scenario-" + self.current_scenario(),
                },
            )
            response = connection.getresponse()
            return http.Response.make(
                response.status,
                response.read(1024 * 1024),
                {"X-TGen-Execution": "paced raw CONNECT probe"},
            )
        except (OSError, http_client.HTTPException):
            self.counts["scenario_transport_failures"] += 1
            return http.Response.make(502, b"raw CONNECT transport failure")
        finally:
            connection.close()

    def record_outcome(
        self,
        flow: http.HTTPFlow,
        status: int | None = None,
        transport_error: str | None = None,
    ) -> None:
        """Append request-scoped response evidence without retaining authentication headers."""
        current = flow.metadata.get("tgen_scenario")
        if not current or "dispatch_path" not in current:
            return
        destination = Path(current["dispatch_path"]).with_name("response-events.jsonl")
        if not destination.resolve().is_relative_to(self.metrics_path.parent.resolve()):
            message = "response evidence escaped the owned results directory"
            raise ValueError(message)
        event = {
            "domain": flow.metadata.get("tgen_request_domain"),
            "synthetic_identity": flow.metadata.get("tgen_synthetic_identity"),
            "sent_at": flow.metadata.get("tgen_request_sent_at"),
            "received_at": time.time(),
            "payload_sha256": flow.metadata.get("tgen_payload_sha256"),
            "worker_marker": flow.metadata.get("tgen_worker", ""),
            "upstream_dispatched": flow.metadata.get("tgen_upstream_dispatched", False),
            "scenario": current["id"],
            "kind": "scenario"
            if current.get("phase") == "execution"
            else "prerequisite",
            "method": flow.metadata.get("tgen_dispatched_method", flow.request.method),
            "path": flow.request.path.split("?", 1)[0],
            "status": status,
            "matched_requirements": flow.metadata.get("tgen_matched_requirements", []),
            "transport_error": transport_error,
            "expected_statuses": current.get("expected_statuses", []),
        }
        if flow.response:
            content_type = flow.response.headers.get("content-type", "")
            body = flow.response.get_text(strict=False) or ""
            event["response_sha256"] = hashlib.sha256(
                flow.response.content or b""
            ).hexdigest()
            event["native_response_identity"] = native_identity(
                event["path"], event["method"], status, content_type, body
            )
            if (
                current.get("functional_contract", {}).get("verifier")
                == "native-dvwa-weak-session"
            ):
                cookies = SimpleCookie()
                cookies.load(flow.response.headers.get("set-cookie", ""))
                event["native_session_id"] = (
                    cookies["dvwaSession"].value if "dvwaSession" in cookies else None
                )
            corpus = current.get("dispatch_contract", {})
            if (
                corpus.get("payloads")
                and current.get("functional_contract", {}).get("verifier")
                == "native-dvwa-corpus"
            ):
                payload = parse_qs(flow.request.path.partition("?")[2]).get(
                    corpus["parameter"], [""]
                )[0]
                event["corpus_payload_sha256"] = hashlib.sha256(
                    payload.encode()
                ).hexdigest()
                event["native_body_verified"] = event["native_response_identity"]
            location = flow.response.headers.get("location", "")
            if status in (301, 302, 307, 308) and not body and location:
                redirect = urlsplit(location)
                event["native_response_identity"] = (
                    redirect.scheme in ("", "http", "https")
                    and not (redirect.username or redirect.password)
                    and (not redirect.hostname or redirect.hostname == event["domain"])
                    and (bool(redirect.path) or bool(redirect.query))
                )
            event["response_assertions"] = {}
            for requirement in current.get("dispatch_contract", {}).get(
                "requirements", []
            ):
                specification = requirement.get("response_contract_by_status", {}).get(
                    str(status), requirement.get("response_contract")
                )
                if requirement["id"] in event["matched_requirements"] and specification:
                    event["response_assertions"][requirement["id"]] = (
                        response_content_matches(specification, content_type, body)
                    )
        event["status_specific_assertions"] = {
            requirement["id"]: event.get("response_assertions", {}).get(
                requirement["id"]
            )
            is True
            for requirement in current.get("dispatch_contract", {}).get(
                "requirements", []
            )
            if requirement["id"] in event["matched_requirements"]
            and str(status) in requirement.get("response_contract_by_status", {})
        }
        event["outcome"] = classify_outcome(event)
        with destination.open("a", encoding="utf-8") as stream:
            destination.chmod(0o600)
            stream.write(json.dumps(event) + "\n")

    def response(self, flow: http.HTTPFlow) -> None:
        """Mitigation is an HTTP outcome, separate from transport failure."""
        if flow.response:
            self.record_outcome(flow, status=flow.response.status_code)
        if flow.response and flow.response.status_code in (403, 429):
            self.counts["attack_mitigated"] += 1
        self.persist()

    def error(self, flow: http.HTTPFlow) -> None:
        """Record failed proxied upstream requests."""
        pending = flow.metadata.pop("tgen_pending_slot", None)
        if pending is not None and not pending.done():
            pending.cancel()
        metadata = flow.metadata.get("tgen_scenario", {})
        marker = {}
        with contextlib.suppress(OSError, ValueError, KeyError):
            marker = json.loads(
                Path(metadata["dispatch_path"])
                .with_name("browser-cleanup.json")
                .read_text()
            )
        if flow.error and declared_socket_cleanup(flow.request.path, metadata, marker):
            self.counts["browser_cleanup_cancellations"] += 1
            self.persist()
            return
        if flow.error:
            self.record_outcome(flow, transport_error=type(flow.error).__name__)
            with (self.metrics_path.parent / "error-events.jsonl").open(
                "a", encoding="utf-8"
            ) as stream:
                stream.write(
                    json.dumps(
                        {
                            "method": flow.metadata.get(
                                "tgen_dispatched_method", flow.request.method
                            ),
                            "path": flow.request.path,
                            "error": re.sub(
                                r"b'[^']*'", "[redacted header]", flow.error.msg
                            ),
                            "worker_marker": flow.metadata.get("tgen_worker", ""),
                            "upstream_dispatched": flow.metadata.get(
                                "tgen_upstream_dispatched", False
                            ),
                            "observed_at": time.time(),
                            "scenario": self.current_scenario(),
                        }
                    )
                    + "\n"
                )
            message = flow.error.msg.lower()
            category = next(
                (
                    word
                    for word in (
                        "client",
                        "killed",
                        "cancel",
                        "disconnected",
                        "connection closed",
                        "reset",
                        "tls",
                        "handshake",
                        "timeout",
                        "eof",
                        "server",
                    )
                    if word in message
                ),
                "other",
            )
            errors = self.counts["error_categories"]
            errors[category] = errors.get(category, 0) + 1
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
