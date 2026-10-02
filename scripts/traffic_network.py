"""Linux network namespace enforcing scanner, subprocess, and browser HTTP pacing."""

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Self

from traffic_common import Pacer, atomic_json, terminate

SUCCESS_MIN, SUCCESS_MAX = 200, 300
CRAPI_ACCOUNT_COUNT = 2


def _proxy_failed(message: str) -> None:
    """Fail startup before any scenario can launch."""
    raise ValueError(message)


class NetworkBoundary:
    """Task-owned isolated egress; only the transparent pacing proxy can reach targets."""

    def __init__(self, root: Path, config: dict, runtime: Path) -> None:
        """Initialize a task-owned egress boundary and benign counters."""
        self.root, self.config, self.runtime = root, config, runtime
        self.state = SimpleNamespace()
        self.browser_temp = Path(tempfile.mkdtemp(prefix="tgen-"))
        suffix = uuid.uuid4().hex[:7]
        self.state.namespace = "tgen-" + suffix
        self.state.host_link, self.state.guest_link = "tgh" + suffix, "tgg" + suffix
        self.state.chain = "TGEN" + suffix.upper()
        self.state.gateway, self.state.guest = "169.254.240.1", "169.254.240.2"
        self.state.proxy_metrics = runtime / "proxy-metrics.json"
        self.state.stop = threading.Event()
        self.state.proxy = None
        self.state.pool = ThreadPoolExecutor(max_workers=200)
        self.state.benign = {
            "benign_requests": 0,
            "benign_success": 0,
            "benign_transport_failures": 0,
            "benign_per_domain": dict.fromkeys(config["domains"], 0),
        }
        self.state.lock = threading.Lock()
        self.state.threads = []
        self.state.netns_dir = Path("/etc/netns") / self.state.namespace
        self.state.started = time.time()
        self.state.tls_context = ssl.create_default_context()
        self.state.local = threading.local()

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
            atomic_json(
                self.runtime / "network-owner.json",
                {
                    "namespace": self.state.namespace,
                    "host_link": self.state.host_link,
                    "chain": self.state.chain,
                    "browser_temp": str(self.browser_temp),
                },
            )
            self.command("ip", "netns", "add", self.state.namespace)
            self.command(
                "ip",
                "link",
                "add",
                self.state.host_link,
                "type",
                "veth",
                "peer",
                "name",
                self.state.guest_link,
            )
            self.command(
                "ip",
                "link",
                "set",
                self.state.guest_link,
                "netns",
                self.state.namespace,
            )
            self.command(
                "ip",
                "addr",
                "add",
                self.state.gateway + "/30",
                "dev",
                self.state.host_link,
            )
            self.command("ip", "link", "set", self.state.host_link, "up")
            self.command(
                "ip",
                "netns",
                "exec",
                self.state.namespace,
                "ip",
                "addr",
                "add",
                self.state.guest + "/30",
                "dev",
                self.state.guest_link,
            )
            self.command(
                "ip",
                "netns",
                "exec",
                self.state.namespace,
                "ip",
                "link",
                "set",
                self.state.guest_link,
                "up",
            )
            self.command(
                "ip",
                "netns",
                "exec",
                self.state.namespace,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            )
            self.command(
                "ip",
                "netns",
                "exec",
                self.state.namespace,
                "ip",
                "route",
                "add",
                "default",
                "via",
                self.state.gateway,
            )
            # DNAT/REDIRECT exposes the original destination to mitmproxy transparent mode.
            self.command("iptables", "-t", "nat", "-N", self.state.chain)
            self.command(
                "iptables",
                "-t",
                "nat",
                "-A",
                self.state.chain,
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
                self.state.host_link,
                "-j",
                self.state.chain,
            )
            # Any tool ignoring HTTP proxies still traverses REDIRECT; non-HTTP egress is denied.
            self.command(
                "iptables",
                "-I",
                "FORWARD",
                "1",
                "-i",
                self.state.host_link,
                "-j",
                "DROP",
            )
            self.command(
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-i",
                self.state.host_link,
                "-p",
                "tcp",
                "--dport",
                "18080",
                "-j",
                "ACCEPT",
            )
            self.command(
                "iptables", "-I", "INPUT", "2", "-i", self.state.host_link, "-j", "DROP"
            )
            # Exact authorized names resolve locally; no external DNS or subnet probing.
            self.state.netns_dir.mkdir(mode=0o700, parents=True)
            hosts = "127.0.0.1 localhost\n"

            for domain in self.config["domains"]:
                addresses = socket.getaddrinfo(
                    domain, 443, socket.AF_INET, socket.SOCK_STREAM
                )
                hosts += str(addresses[0][4][0]) + " " + domain + "\n"
            (self.state.netns_dir / "hosts").write_text(hosts)
            environment = dict(
                os.environ,
                TGEN_DOMAINS=json.dumps(self.config["domains"]),
                TGEN_PROXY_METRICS=str(self.state.proxy_metrics),
            )
            proxy_log = (self.runtime / "proxy.log").open("ab")
            self.state.proxy = subprocess.Popen(  # noqa: S603 - fixed verified proxy invocation
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
            if self.state.proxy.poll() is not None:
                msg = "transparent pacing proxy failed to start"
                _proxy_failed(msg)
            for domain in self.config["domains"]:
                worker = threading.Thread(
                    target=self.benign_loop, args=(domain,), daemon=True
                )
                worker.start()
                self.state.threads.append(worker)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def request(self, domain: str) -> None:
        """Send one independently paced benign control, with validated upstream TLS."""
        success, failed = False, False
        if not hasattr(self.state.local, "connections"):
            self.state.local.connections = {}
        connection = self.state.local.connections.get(domain)
        if connection is None:
            connection = http.client.HTTPSConnection(
                domain, context=self.state.tls_context, timeout=10
            )
            self.state.local.connections[domain] = connection
        try:
            connection.request(
                "GET",
                "/httpbin/get",
                headers={
                    "X-TGen-Class": "benign",
                    "X-MUD-User": "waap-benign-" + domain,
                },
            )
            response = connection.getresponse()
            success = SUCCESS_MIN <= response.status < SUCCESS_MAX
            response.read()
        except (OSError, http.client.HTTPException):
            failed = True
            connection.close()
            self.state.local.connections.pop(domain, None)
        with self.state.lock:
            self.state.benign["benign_success"] += int(success)
            self.state.benign["benign_transport_failures"] += int(failed)

    def benign_loop(self, domain: str) -> None:
        """Offer 90 launches/sec to each domain without burst credit."""
        pacer = Pacer(90)
        while not self.state.stop.is_set():
            pacer.acquire()
            with self.state.lock:
                self.state.benign["benign_requests"] += 1
                self.state.benign["benign_per_domain"][domain] += 1
            self.state.pool.submit(self.request, domain)

    def wrap(self, command: list[str], connection: bool = False) -> list[str]:
        """All HTTP scenario descendants inherit the same isolated egress."""
        return (
            command
            if connection
            else [
                "ip",
                "netns",
                "exec",
                self.state.namespace,
                "setpriv",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                *command,
            ]
        )

    def fixture_login(self, domain: str, path: str, body: dict) -> dict:
        """Pace benign synthetic account authentication at the same enforced HTTP boundary."""
        command = self.wrap(
            [
                "curl",
                "-sk",
                "--max-time",
                "10",
                "-X",
                "POST",
                "https://" + domain + path,
                "-H",
                "Content-Type: application/json",
                "-H",
                "X-MUD-User: waap-fixture-benign",
                "-d",
                json.dumps(body),
            ]
        )
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603 - fixed allowlisted paced fixture login
        try:
            return json.loads(result.stdout)
        except ValueError:
            return {}

    def refresh_fixtures(self, domain: str) -> None:
        """Generate/renew real tokens for public seeded lab accounts without disabling WAAP."""
        fixture_path = self.runtime.parent / "fixtures.json"
        fixtures = json.loads(fixture_path.read_text()) if fixture_path.exists() else {}
        vampi = self.fixture_login(
            domain, "/vampi/users/v1/login", {"username": "name1", "password": "pass1"}
        ).get("auth_token")
        if vampi:
            fixtures["vampi_token"] = vampi
        crapi = []
        for email, password in (
            ("adam007@example.com", "adam007!123"),
            ("pogba006@example.com", "pogba006!123"),
        ):
            token = self.fixture_login(
                domain,
                "/crapi/identity/api/auth/login",
                {"email": email, "password": password},
            ).get("token")
            if token:
                crapi.append(token)
        if len(crapi) == CRAPI_ACCOUNT_COUNT:
            fixtures["crapi_tokens"] = crapi
        juice = (
            self.fixture_login(
                domain,
                "/juice-shop/rest/user/login",
                {"email": "admin@juice-sh.op", "password": "admin123"},
            )
            .get("authentication", {})
            .get("token")
        )
        if juice:
            fixtures["juice_token"] = juice
        atomic_json(fixture_path, fixtures)

    def environment(self, scenario: dict, domain: str, directory: Path) -> dict:
        """Provide structured inputs and private per-scenario output paths."""
        fixtures = json.loads((self.runtime.parent / "fixtures.json").read_text())
        return dict(
            os.environ,
            SSL_CERT_FILE=str(self.runtime / "mitm-ca/mitmproxy-ca-cert.pem"),
            REQUESTS_CA_BUNDLE=str(self.runtime / "mitm-ca/mitmproxy-ca-cert.pem"),
            NODE_EXTRA_CA_CERTS=str(self.runtime / "mitm-ca/mitmproxy-ca-cert.pem"),
            TGEN_INHERITED_BOUNDARY="1",
            TGEN_NUCLEI_TEMPLATES=",".join(
                "/opt/nuclei-templates/http/" + name
                for name in (
                    "technologies/tech-detect.yaml",
                    "misconfiguration/http-missing-security-headers.yaml",
                    "vulnerabilities/odoo-xss.yaml",
                    "vulnerabilities/bentoml-ssrf.yaml",
                )
            ),
            TGEN_PARAMETER_WORDLIST=str(self.root / "suites/parameter-words.txt"),
            TGEN_FIXTURES=str(self.runtime.parent / "fixtures.json"),
            TGEN_CRAPI_VEHICLE_UUID=str(fixtures.get("crapi_vehicle_uuid", "")),
            TGEN_CRAPI_VIDEO_ID=str(fixtures.get("crapi_video_id", "")),
            TGEN_CRAPI_ORDER_ID=str(fixtures.get("crapi_order_id", "")),
            TARGET_FQDN=domain,
            TARGET_PROTOCOL="https",
            CRAPI_BASE_URL="https://" + domain + "/crapi",
            TARGET_URL="https://" + domain + "/juice-shop/",
            TGEN_RESULTS_DIR=str(directory),
            RESULTS_DIR=str(directory),
            TMPDIR=str(self.browser_temp),
            TGEN_CONNECTION_RATE=str(self.config["connection_rps"]),
            TGEN_SLOW_CONNECTIONS=str(self.config["slow_connections"]),
            TGEN_DURATION="15",
            TGEN_SCANNER_SECONDS="30",
            TGEN_REQUEST_TIMEOUT="15",
            TGEN_REPEAT_COUNT="5",
            TGEN_GRAPHQL_BATCH_MAX="10",
            TGEN_GRAPHQL_FIELDS_MAX="50",
            TGEN_ZAP_SPIDER_MINUTES="1",
            TGEN_ZAP_SCAN_MINUTES="2",
            TGEN_BROWSER_IDENTITIES="2",
            TGEN_CONCURRENCY="20",
            TGEN_REQUESTS="100",
            TGEN_REQUESTS_PER_WORKER="5",
            SOURCE_COMMIT=self.config["source_commit"],
            TGEN_ARTIFACT_SHA256=self.config["artifact_sha256"],
            TGEN_AUTHORIZED_HOST=domain,
            RUN_ID="waap-" + uuid.uuid4().hex,
            CSD_SCENARIO=scenario.get("scenario", ""),
        )

    def metrics(self) -> dict:
        """Read private aggregate metrics, separating controls and attack outcomes."""
        try:
            attack = json.loads(self.state.proxy_metrics.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            attack = {}
        with self.state.lock:
            return {
                **self.state.benign,
                **attack,
                "elapsed": time.time() - self.state.started,
            }

    def __exit__(self, *_: object) -> None:
        """Remove only this boundary's namespaces/rules and close every worker."""
        self.state.stop.set()
        for thread in self.state.threads:
            thread.join(2)
        self.state.pool.shutdown(wait=True, cancel_futures=True)
        if self.state.proxy:
            terminate(self.state.proxy)
        commands = [
            ["iptables", "-D", "INPUT", "-i", self.state.host_link, "-j", "DROP"],
            [
                "iptables",
                "-D",
                "INPUT",
                "-i",
                self.state.host_link,
                "-p",
                "tcp",
                "--dport",
                "18080",
                "-j",
                "ACCEPT",
            ],
            ["iptables", "-D", "FORWARD", "-i", self.state.host_link, "-j", "DROP"],
            [
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-i",
                self.state.host_link,
                "-j",
                self.state.chain,
            ],
            ["iptables", "-t", "nat", "-F", self.state.chain],
            ["iptables", "-t", "nat", "-X", self.state.chain],
            ["ip", "link", "delete", self.state.host_link],
            ["ip", "netns", "delete", self.state.namespace],
        ]
        for command in commands:
            subprocess.run(  # noqa: S603 - fixed network setup/cleanup argv
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        shutil.rmtree(self.browser_temp)
        (self.runtime / "network-owner.json").unlink(missing_ok=True)
        if hasattr(self.state, "netns_dir") and self.state.netns_dir.exists():
            shutil.rmtree(self.state.netns_dir)
