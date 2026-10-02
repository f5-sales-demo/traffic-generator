"""Linux network namespace enforcing scanner, subprocess, and browser HTTP pacing."""

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Self

from traffic_runtime import Pacer, terminate

SUCCESS_MIN, SUCCESS_MAX = 200, 300


def _proxy_failed(message: str) -> None:
    """Fail startup before any scenario can launch."""
    raise ValueError(message)


class NetworkBoundary:
    """Task-owned isolated egress; only the transparent pacing proxy can reach targets."""

    def __init__(self, root: Path, config: dict, runtime: Path) -> None:
        """Initialize a task-owned egress boundary and benign counters."""
        self.root, self.config, self.runtime = root, config, runtime
        suffix = uuid.uuid4().hex[:7]
        self.namespace = "tgen-" + suffix
        self.host_link, self.guest_link = "tgh" + suffix, "tgg" + suffix
        self.chain = "TGEN" + suffix.upper()
        self.gateway, self.guest = "169.254.240.1", "169.254.240.2"
        self.proxy_metrics = runtime / "proxy-metrics.json"
        self.stop = threading.Event()
        self.proxy = None
        self.pool = ThreadPoolExecutor(max_workers=200)
        self.benign = {
            "benign_requests": 0,
            "benign_success": 0,
            "benign_transport_failures": 0,
            "benign_per_domain": dict.fromkeys(config["domains"], 0),
        }
        self.lock = threading.Lock()
        self.threads = []
        self.started = time.time()
        self.tls_context = ssl.create_default_context()
        self.local = threading.local()

    def command(self, *args: str) -> None:
        """Execute fixed argv; never evaluate generated shell source."""
        subprocess.run(  # noqa: S603 - fixed network setup/cleanup argv
            list(args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )

    def __enter__(self) -> Self:
        """Create isolated namespace and a task-owned transparent HTTP gateway."""
        if os.geteuid() != 0:
            msg = "network pacing requires root in the supervised service"
            raise ValueError(msg)
        try:
            self.command("ip", "netns", "add", self.namespace)
            self.command(
                "ip",
                "link",
                "add",
                self.host_link,
                "type",
                "veth",
                "peer",
                "name",
                self.guest_link,
            )
            self.command("ip", "link", "set", self.guest_link, "netns", self.namespace)
            self.command(
                "ip", "addr", "add", self.gateway + "/30", "dev", self.host_link
            )
            self.command("ip", "link", "set", self.host_link, "up")
            self.command(
                "ip",
                "netns",
                "exec",
                self.namespace,
                "ip",
                "addr",
                "add",
                self.guest + "/30",
                "dev",
                self.guest_link,
            )
            self.command(
                "ip",
                "netns",
                "exec",
                self.namespace,
                "ip",
                "link",
                "set",
                self.guest_link,
                "up",
            )
            self.command(
                "ip", "netns", "exec", self.namespace, "ip", "link", "set", "lo", "up"
            )
            self.command(
                "ip",
                "netns",
                "exec",
                self.namespace,
                "ip",
                "route",
                "add",
                "default",
                "via",
                self.gateway,
            )
            # DNAT/REDIRECT exposes the original destination to mitmproxy transparent mode.
            self.command("iptables", "-t", "nat", "-N", self.chain)
            self.command(
                "iptables",
                "-t",
                "nat",
                "-A",
                self.chain,
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                "80,443",
                "-j",
                "REDIRECT",
                "--to-ports",
                "18080",
            )
            self.command(
                "iptables",
                "-t",
                "nat",
                "-I",
                "PREROUTING",
                "1",
                "-i",
                self.host_link,
                "-j",
                self.chain,
            )
            # Any tool ignoring HTTP proxies still traverses REDIRECT; non-HTTP egress is denied.
            self.command(
                "iptables", "-I", "FORWARD", "1", "-i", self.host_link, "-j", "DROP"
            )
            self.command(
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-i",
                self.host_link,
                "-p",
                "tcp",
                "--dport",
                "18080",
                "-j",
                "ACCEPT",
            )
            self.command(
                "iptables", "-I", "INPUT", "2", "-i", self.host_link, "-j", "DROP"
            )
            # Exact authorized names resolve locally; no external DNS or subnet probing.
            self.netns_dir = Path("/etc/netns") / self.namespace
            self.netns_dir.mkdir(mode=0o700, parents=True)
            hosts = "127.0.0.1 localhost\n"

            for domain in self.config["domains"]:
                addresses = socket.getaddrinfo(
                    domain, 443, socket.AF_INET, socket.SOCK_STREAM
                )
                hosts += addresses[0][4][0] + " " + domain + "\n"
            (self.netns_dir / "hosts").write_text(hosts)
            environment = dict(
                os.environ,
                TGEN_DOMAINS=json.dumps(self.config["domains"]),
                TGEN_PROXY_METRICS=str(self.proxy_metrics),
            )
            proxy_log = (self.runtime / "proxy.log").open("ab")
            self.proxy = subprocess.Popen(  # noqa: S603 - fixed verified proxy invocation
                [
                    shutil.which("mitmdump") or "/usr/local/bin/mitmdump",
                    "--mode",
                    "transparent",
                    "--listen-port",
                    "18080",
                    "--set",
                    "block_global=false",
                    "--set",
                    "connection_strategy=lazy",
                    "--set",
                    "confdir=" + str(self.runtime / "mitm-ca"),
                    "-s",
                    str(self.root / "scripts/traffic_proxy.py"),
                    "-q",
                ],
                stdout=proxy_log,
                stderr=subprocess.STDOUT,
                env=environment,
                start_new_session=True,
            )
            proxy_log.close()
            time.sleep(2)
            if self.proxy.poll() is not None:
                msg = "transparent pacing proxy failed to start"
                _proxy_failed(msg)
            for domain in self.config["domains"]:
                worker = threading.Thread(
                    target=self.benign_loop, args=(domain,), daemon=True
                )
                worker.start()
                self.threads.append(worker)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        else:
            return self

    def request(self, domain: str) -> None:
        """Send one independently paced benign control, with validated upstream TLS."""
        success, failed = False, False
        if not hasattr(self.local, "connections"):
            self.local.connections = {}
        connection = self.local.connections.get(domain)
        if connection is None:
            connection = http.client.HTTPSConnection(
                domain, context=self.tls_context, timeout=10
            )
            self.local.connections[domain] = connection
        try:
            connection.request(
                "GET", "/httpbin/get", headers={"X-TGen-Class": "benign"}
            )
            response = connection.getresponse()
            success = SUCCESS_MIN <= response.status < SUCCESS_MAX
            response.read()
        except (OSError, http.client.HTTPException):
            failed = True
            connection.close()
            self.local.connections.pop(domain, None)
        with self.lock:
            self.benign["benign_success"] += int(success)
            self.benign["benign_transport_failures"] += int(failed)

    def benign_loop(self, domain: str) -> None:
        """Offer 90 launches/sec to each domain without burst credit."""
        pacer = Pacer(90)
        while not self.stop.is_set():
            pacer.acquire()
            with self.lock:
                self.benign["benign_requests"] += 1
                self.benign["benign_per_domain"][domain] += 1
            self.pool.submit(self.request, domain)

    def wrap(self, command: list[str], connection: bool = False) -> list[str]:
        """All HTTP scenario descendants inherit the same isolated egress."""
        return (
            command if connection else ["ip", "netns", "exec", self.namespace, *command]
        )

    def environment(self, scenario: dict, domain: str, directory: Path) -> dict:
        """Provide structured inputs and private per-scenario output paths."""
        return dict(
            os.environ,
            SSL_CERT_FILE=str(self.runtime / "mitm-ca/mitmproxy-ca-cert.pem"),
            REQUESTS_CA_BUNDLE=str(self.runtime / "mitm-ca/mitmproxy-ca-cert.pem"),
            NODE_EXTRA_CA_CERTS=str(self.runtime / "mitm-ca/mitmproxy-ca-cert.pem"),
            TGEN_INHERITED_BOUNDARY="1",
            TGEN_FIXTURES=str(self.runtime.parent / "fixtures.json"),
            TARGET_FQDN=domain,
            TARGET_PROTOCOL="https",
            CRAPI_BASE_URL="https://" + domain + "/crapi",
            TARGET_URL="https://" + domain + "/juice-shop/",
            TGEN_RESULTS_DIR=str(directory),
            RESULTS_DIR=str(directory),
            TMPDIR=str(directory),
            TGEN_CONNECTION_RATE=str(self.config["connection_rps"]),
            TGEN_SLOW_CONNECTIONS=str(self.config["slow_connections"]),
            TGEN_DURATION="15",
            TGEN_CONCURRENCY="20",
            TGEN_REQUESTS="100",
            SOURCE_COMMIT=self.config["source_commit"],
            TGEN_ARTIFACT_SHA256=self.config["artifact_sha256"],
            TGEN_AUTHORIZED_HOST=domain,
            RUN_ID="waap-" + uuid.uuid4().hex,
            CSD_SCENARIO=scenario.get("scenario", ""),
        )

    def metrics(self) -> dict:
        """Read private aggregate metrics, separating controls and attack outcomes."""
        try:
            attack = json.loads(self.proxy_metrics.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            attack = {}
        with self.lock:
            return {**self.benign, **attack, "elapsed": time.time() - self.started}

    def __exit__(self, *_: object) -> None:
        """Remove only this boundary's namespaces/rules and close every worker."""
        self.stop.set()
        for thread in self.threads:
            thread.join(2)
        self.pool.shutdown(wait=True, cancel_futures=True)
        if self.proxy:
            terminate(self.proxy)
        commands = [
            ["iptables", "-D", "INPUT", "-i", self.host_link, "-j", "DROP"],
            [
                "iptables",
                "-D",
                "INPUT",
                "-i",
                self.host_link,
                "-p",
                "tcp",
                "--dport",
                "18080",
                "-j",
                "ACCEPT",
            ],
            ["iptables", "-D", "FORWARD", "-i", self.host_link, "-j", "DROP"],
            [
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-i",
                self.host_link,
                "-j",
                self.chain,
            ],
            ["iptables", "-t", "nat", "-F", self.chain],
            ["iptables", "-t", "nat", "-X", self.chain],
            ["ip", "link", "delete", self.host_link],
            ["ip", "netns", "delete", self.namespace],
        ]
        for command in commands:
            subprocess.run(  # noqa: S603 - fixed network setup/cleanup argv
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if hasattr(self, "netns_dir") and self.netns_dir.exists():
            shutil.rmtree(self.netns_dir)
