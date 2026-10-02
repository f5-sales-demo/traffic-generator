#!/usr/bin/env python3
"""Private, bounded catalog execution with one shared HTTP pacing boundary."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from traffic_catalog import load_catalog, readiness
from traffic_common import atomic_json, terminate
from traffic_network import NetworkBoundary

DOMAIN_COUNT = 2


def validate_config(config: dict) -> None:
    """Fail closed on targets, immutable provenance, or relaxed safety bounds."""
    if config.get("schema_version") != 1:
        msg = "unsupported configuration schema"
        raise ValueError(msg)
    allowed = {
        "schema_version",
        "domains",
        "protocol",
        "http_rps",
        "benign_rps",
        "attack_rps",
        "connection_rps",
        "slow_connections",
        "csd_enabled",
        "protections_enabled",
        "scenario_timeout_seconds",
        "retention_days",
        "retention_bytes",
        "results_dir",
        "source_commit",
        "artifact_sha256",
    }
    if set(config) != allowed:
        message = "configuration keys are missing or unknown"
        raise ValueError(message)
    domains = config.get("domains", [])
    if (
        len(domains) != DOMAIN_COUNT
        or len(set(domains)) != DOMAIN_COUNT
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", d) for d in domains
        )
    ):
        msg = "exactly two distinct authorized domain names are required"
        raise ValueError(msg)
    if (
        config.get("protocol") != "https"
        or config.get("protections_enabled") is not True
        or config.get("csd_enabled") is not False
    ):
        msg = "HTTPS and enabled WAAP protections with disabled CSD are required"
        raise ValueError(msg)
    if (config.get("http_rps"), config.get("benign_rps"), config.get("attack_rps")) != (
        200,
        180,
        20,
    ):
        msg = "aggregate budget must be 180 benign plus 20 attack requests/sec"
        raise ValueError(msg)
    for key, limit in (
        ("connection_rps", 20),
        ("slow_connections", 20),
        ("scenario_timeout_seconds", 900),
        ("retention_days", 7),
        ("retention_bytes", 10 * 1024**3),
    ):
        if (
            not isinstance(config.get(key), int)
            or isinstance(config.get(key), bool)
            or not 0 < config[key] <= limit
        ):
            raise ValueError("invalid safety bound: " + key)
    if not re.fullmatch(
        r"[a-f0-9]{40}", config.get("source_commit", "")
    ) or not re.fullmatch(r"[a-f0-9]{64}", config.get("artifact_sha256", "")):
        msg = "immutable source commit and artifact digest are required"
        raise ValueError(msg)
    if not Path(config.get("results_dir", "")).is_absolute():
        msg = "absolute private results directory required"
        raise ValueError(msg)


def _expired(command: list[str], timeout: float) -> None:
    """Convert an elapsed monotonic deadline into the explicit timeout result."""
    raise subprocess.TimeoutExpired(command, timeout)


def execute(
    command: list[str],
    log: Path,
    environment: dict,
    timeout: float,
    stop: threading.Event | None = None,
    monitor: Callable[[], str | None] | None = None,
) -> dict:
    """Deadline and descendant cleanup apply even after a successful parent exit."""
    started = time.time()
    log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with log.open("wb") as output:
        log.chmod(0o600)
        with subprocess.Popen(  # noqa: S603 - argv from validated explicit catalog
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=environment.get("TGEN_NESTED_EXECUTION") != "1",
        ) as process:
            try:
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if stop is not None and stop.is_set():
                        outcome, code = "interrupted", 130
                        break
                    if monitor is not None and (failure := monitor()):
                        outcome, code = failure, 125
                        break
                    if time.monotonic() >= deadline:
                        _expired(command, timeout)
                    time.sleep(0.05)
                else:
                    code = process.returncode
                    outcome = "launched" if code == 0 else "tool_failure"
            except subprocess.TimeoutExpired:
                code, outcome = 124, "timeout"
            finally:
                terminate(
                    process, group=environment.get("TGEN_NESTED_EXECUTION") != "1"
                )
    if not log.exists():
        log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        log.write_text("Scenario removed its owned evidence log.\n")
        log.chmod(0o600)
        outcome = "tool_failure"
    text = log.read_text(errors="replace")
    if outcome == "launched" and re.search(
        r"(?im)^\s*(\[SKIP\]|SKIP:|.*No (?:video|order) ID available|WARN: Could not extract auth token|.*Could not (?:setup|authenticate|retrieve vehicle)|.*Skipping (?:verification|exploit|JWT))",
        text,
    ):
        outcome = "fixture_failure"
    return {
        "started": started,
        "completed": time.time(),
        "exit_code": code,
        "outcome": outcome,
    }


def retain(root: Path, active: Path, days: int, max_bytes: int) -> None:
    """Evict oldest detailed runs by age then total bytes; preserve active evidence."""
    candidates = sorted(
        (
            p
            for p in root.iterdir()
            if p.is_dir()
            and p.name.startswith("pass-")
            and p != active
            and not p.is_symlink()
        ),
        key=lambda p: p.stat().st_mtime,
    )
    sizes = {
        p: sum(
            f.stat().st_size for f in p.rglob("*") if f.is_file() and not f.is_symlink()
        )
        for p in [*candidates, active]
        if p.exists()
    }
    total = sum(sizes.values())
    for path in candidates:
        if path.stat().st_mtime < time.time() - days * 86400 or total > max_bytes:
            shutil.rmtree(path)
            total -= sizes[path]
    # Evict completed scenario detail while preserving the active pass and executing scenario.
    if active.exists():
        for directory in sorted(
            (p for p in active.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime
        ):
            receipt = directory / "receipt.json"
            if receipt.exists() and (
                time.time() - directory.stat().st_mtime > days * 86400
                or total > max_bytes
            ):
                detail_bytes = sum(
                    path.stat().st_size
                    for path in directory.rglob("*")
                    if path.is_file()
                )
                shutil.rmtree(directory)
                total -= detail_bytes


def evidence_monitor(
    runtime: Path, active: Path, config: dict
) -> Callable[[], str | None]:
    """Enforce retention during execution and stop writers before exhausting the detail cap."""
    next_check = 0.0

    def check() -> str | None:
        nonlocal next_check
        if time.monotonic() < next_check:
            return None
        next_check = time.monotonic() + 0.5
        retain(runtime, active, config["retention_days"], config["retention_bytes"])
        size = sum(
            path.stat().st_size
            for path in runtime.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        if size >= max(0, config["retention_bytes"] - 1024 * 1024):
            return "evidence_failure"
        return None

    return check


def scenario_command(root: Path, scenario: dict, domain: str) -> list[str]:
    """Use explicit interpreters; connection probes use separately paced equivalents."""
    if scenario.get("adapter") == "bounded-benchmark":
        return [
            "python3",
            str(root / "scripts/traffic_benchmark.py"),
            scenario["id"],
            domain,
        ]
    if scenario["budget"] == "connection":
        return [
            "python3",
            str(root / "scripts/traffic_connections.py"),
            scenario["id"],
            domain,
        ]
    if scenario["kind"] == "csd-browser":
        return [
            "node",
            str(root / "suites/csd-violations/azure.mjs"),
            scenario["scenario"],
        ]
    return [
        "node" if scenario["kind"] == "javascript" else "bash",
        str(root / scenario["entrypoint"]),
        domain,
    ]


def run_nested(root: Path, scenarios: list[dict]) -> int:
    """Nested suite stress inherits the single egress boundary and emits child receipts."""
    results = Path(os.environ["TGEN_RESULTS_DIR"])
    failed = False
    for scenario in scenarios:
        directory = results / scenario["id"].replace("/", "--")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        command = scenario_command(root, scenario, os.environ["TARGET_FQDN"])
        # Native connection tools cannot bypass the isolated HTTP egress from nested runs.
        if scenario["budget"] == "connection":
            result = {
                "id": scenario["id"],
                "outcome": "fixture_failure",
                "reason": "connection behavior must run in the sequential top-level catalog",
            }
        else:
            environment = dict(
                os.environ,
                TGEN_NESTED_EXECUTION="1",
                TGEN_RESULTS_DIR=str(directory),
                RESULTS_DIR=str(directory),
            )
            result = execute(
                command,
                directory / "scenario.log",
                environment,
                scenario["timeout_seconds"],
            )
        atomic_json(directory / "receipt.json", result)
        failed |= result["outcome"] != "launched"
    return int(failed)


def _scenario(
    root: Path,
    scenario: dict,
    domain: str,
    active: Path,
    boundary: NetworkBoundary,
    state: dict,
    stop: threading.Event,
) -> dict:
    """Launch one scenario and record meaningful network dispatch independently of filler."""
    config = boundary.config
    atomic_json(
        Path(config["results_dir"]) / "current-scenario.json", {"id": scenario["id"]}
    )
    directory = active / scenario["id"].replace("/", "--")
    directory.mkdir(mode=0o700)
    boundary.refresh_fixtures(domain)
    environment = boundary.environment(scenario, domain, directory)
    before = boundary.metrics()
    command = boundary.wrap(
        scenario_command(root, scenario, domain),
        connection=scenario["budget"] == "connection",
    )
    result = execute(
        command,
        directory / "scenario.log",
        environment,
        min(config["scenario_timeout_seconds"], scenario["timeout_seconds"]),
        stop,
        monitor=evidence_monitor(Path(config["results_dir"]), active, config),
    )
    after = boundary.metrics()
    result.update(
        {
            "id": scenario["id"],
            "source_sha256": hashlib.sha256(
                (root / scenario["entrypoint"]).read_bytes()
            ).hexdigest(),
            "http_requests": after.get("scenario_requests", 0)
            - before.get("scenario_requests", 0),
            "claim": scenario["expected_outcome"],
        }
    )
    if scenario["budget"] == "connection":
        connection_receipt = directory / "connections.json"
        if connection_receipt.exists():
            connection_data = json.loads(connection_receipt.read_text())
            result["connection_attempts"] = connection_data["attempts"]
            result["connection_limit"] = connection_data["attempt_limit_per_second"]
        else:
            result["outcome"] = "tool_failure"
    result["mitigated_requests"] = after.get("attack_mitigated", 0) - before.get(
        "attack_mitigated", 0
    )
    result["transport_failures"] = after.get(
        "scenario_transport_failures", 0
    ) - before.get("scenario_transport_failures", 0)
    result["tool_cancellations"] = after.get("tool_cancellations", 0) - before.get(
        "tool_cancellations", 0
    )
    if scenario["kind"] == "javascript":
        log_text = (directory / "scenario.log").read_text(errors="replace")
        if re.search(
            r"(?m)^\s*(Registrations attempted|Contact forms submitted): 0$", log_text
        ):
            result["outcome"] = "fixture_failure"
    if result["outcome"] == "launched" and result["transport_failures"]:
        result["outcome"] = "transport_failure"
    if scenario["budget"] == "http" and result["http_requests"] == 0:
        result["outcome"] = "fixture_failure"
    if result["outcome"] != "launched":
        state["failures"] = (
            state["failures"] + [{"id": scenario["id"], "outcome": result["outcome"]}]
        )[-200:]
    atomic_json(directory / "receipt.json", result)
    return result


def _heartbeat(
    boundary: NetworkBoundary, stop: threading.Event, state: dict, status_path: Path
) -> threading.Thread:
    """Publish private liveness and measured traffic while a scenario runs."""

    def heartbeat() -> None:
        while not stop.wait(2):
            state["heartbeat"] = time.time()
            state["rates"] = boundary.metrics()
            atomic_json(status_path, state)

    worker = threading.Thread(target=heartbeat, daemon=True)
    worker.start()
    return worker


def run(root: Path, scenarios: list[dict], config_path: Path, continuous: bool) -> int:
    """Supervise perpetual passes; failures remain visible while subsequent launches continue."""
    config = json.loads(config_path.read_text())
    validate_config(config)
    if not readiness(root, load_catalog(root))["ready"]:
        raise ValueError(
            "missing catalog dependencies: "
            + ",".join(readiness(root, load_catalog(root))["missing_tools"])
        )

    runtime = Path(config["results_dir"])
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    status_path = runtime / "status.json"
    old = json.loads(status_path.read_text()) if status_path.exists() else {}
    state = {
        "schema_version": 1,
        "status": "starting",
        "run_started": time.time(),
        "source_commit": config["source_commit"],
        "artifact_sha256": config["artifact_sha256"],
        "configured_rates": {
            "http": 200,
            "benign": 180,
            "attack": 20,
            "connection": 20,
        },
        "completed_passes": old.get("completed_passes", 0),
        "previous_run_interrupted": old.get("status") in ("running", "starting"),
        "failures": [],
        "current_scenario": None,
    }
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    with NetworkBoundary(root, config, runtime) as boundary:
        worker = _heartbeat(boundary, stop, state, status_path)
        state["status"] = "running"
        while not stop.is_set():
            pass_id = "pass-" + uuid.uuid4().hex
            active = runtime / pass_id
            active.mkdir(mode=0o700)
            receipts = []
            state["pass_started"] = time.time()
            for index, scenario in enumerate(scenarios):
                if stop.is_set():
                    break
                state["current_scenario"] = scenario["id"]
                result = _scenario(
                    root,
                    scenario,
                    config["domains"][index % 2],
                    active,
                    boundary,
                    state,
                    stop,
                )
                receipts.append(result)
                retain(
                    runtime, active, config["retention_days"], config["retention_bytes"]
                )
            receipt = {
                "id": pass_id,
                "started": state["pass_started"],
                "complete": len(receipts) == len(scenarios),
                "catalog_complete": len(receipts)
                == len(load_catalog(root)["scenarios"]),
                "scenario_count": len(receipts),
                "passed": len(receipts) == len(scenarios)
                and all(r["outcome"] == "launched" for r in receipts),
                "scenarios": receipts,
                "completed": time.time(),
            }
            atomic_json(active / "receipt.json", receipt)
            if receipt["catalog_complete"]:
                state["completed_passes"] += 1
            state["last_pass"] = {k: v for k, v in receipt.items() if k != "scenarios"}
            state["catalog_passes"] = (
                [*state.get("catalog_passes", []), state["last_pass"]]
            )[-2:]
            if not continuous:
                stop.set()
        worker.join(3)
    state.update(status="stopped", current_scenario=None, heartbeat=time.time())
    atomic_json(status_path, state)
    return 0 if not state["failures"] else 1


def main() -> int:
    """Continuous service entrypoint."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--suite", default="catalog")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    scenarios = [
        s
        for s in load_catalog(root)["scenarios"]
        if args.suite in ("catalog", s["suite"])
    ]
    if os.environ.get("TGEN_INHERITED_BOUNDARY") == "1":
        return run_nested(root, scenarios)
    return run(root, scenarios, args.config, not args.once)


if __name__ == "__main__":
    raise SystemExit(main())
