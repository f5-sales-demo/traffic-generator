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
import sys
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from catalog_pass_receipt import pass_traffic
from crapi_otp_fixture import verify_restoration
from scanner_phase_contract import verify_scanner_phases
from stress_reports import native_report_verification
from traffic_catalog import load_catalog, readiness
from traffic_child_metadata import child_dispatch
from traffic_command import scenario_command
from traffic_common import atomic_json, terminate
from traffic_dispatch import (
    verify_browser_actions,
    verify_connection_probe,
    verify_dispatch,
    verify_responses,
    verify_route_actions,
    verify_tool_actions,
    verify_workload,
)
from traffic_family_native import host_action as family_host_action
from traffic_fixture_recovery import recover_fixtures
from traffic_functional import verify_functional
from traffic_network import NetworkBoundary
from traffic_order_host import restore_receipt
from traffic_pass import current_pass_receipt
from traffic_report import build_report
from traffic_security import attributed_responses, await_control_evidence
from traffic_tool import native_binary

sys.dont_write_bytecode = True
DOMAIN_COUNT = 2
BROWSER_RECEIPT_VERSION = 2


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
        ("scenario_timeout_seconds", 7200),
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


def detail_size(root: Path) -> int:
    """Count detail while concurrent atomic writers rename temporary files."""
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except FileNotFoundError:
            continue
    return total


def prune_child_markers(root: Path) -> None:
    """Remove attribution markers only after their owned scenario directory is evicted."""
    markers = root / "children"
    if markers.is_symlink():
        return
    for marker in markers.glob("*.json"):
        if marker.is_symlink():
            continue
        try:
            destination = Path(
                json.loads(marker.read_text())["dispatch_path"]
            ).resolve()
            relative = destination.relative_to(root.resolve())
            if (
                relative.parts[0].startswith("pass-")
                and not destination.parent.exists()
            ):
                marker.unlink(missing_ok=True)
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            continue


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
    sizes = {p: detail_size(p) for p in [*candidates, active] if p.exists()}
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
                detail_bytes = detail_size(directory)
                shutil.rmtree(directory)
                total -= detail_bytes

    prune_child_markers(root)


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
        size = detail_size(runtime)
        if size >= max(0, config["retention_bytes"] - 1024 * 1024):
            return "evidence_failure"
        return None

    return check


def run_nested(root: Path, scenarios: list[dict]) -> int:
    """Nested suite stress inherits the single egress boundary and emits child receipts."""
    results = Path(os.environ["TGEN_RESULTS_DIR"])
    results.mkdir(parents=True, exist_ok=True, mode=0o700)
    failed = False
    for scenario in scenarios:
        directory = results / scenario["id"].replace("/", "--")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        runtime_directory = Path(os.environ["TGEN_RUNTIME_DIR"])
        marker = "child-" + uuid.uuid4().hex
        metadata = child_dispatch(scenario, directory)
        (runtime_directory / "children").mkdir(mode=0o700, exist_ok=True)
        atomic_json(runtime_directory / "children" / (marker + ".json"), metadata)
        tools = directory / "child-tools"
        tools.mkdir(mode=0o700, exist_ok=True)
        for tool in {
            "curl",
            *[
                requirement["tool"]
                for requirement in scenario.get("tool_contract", {}).get(
                    "requirements", []
                )
            ],
        }:
            binary = native_binary(tool, os.environ["PATH"], runtime_directory)
            wrapper = tools / tool
            wrapper.write_text(
                "#!/usr/bin/env python3\nimport os,sys\nos.execv(sys.executable,[sys.executable,"
                + repr(str(root / "scripts/traffic_tool.py"))
                + ","
                + repr(binary)
                + ","
                + repr(tool)
                + ",*sys.argv[1:]])\n"
            )
            wrapper.chmod(0o700)
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
                TGEN_CHILD_MARKER=marker,
                TGEN_TOOL_CONTRACT=json.dumps(
                    scenario.get("tool_contract", {"requirements": []})
                ),
                PATH=str(tools) + os.pathsep + os.environ["PATH"],
                TGEN_RESULTS_DIR=str(directory),
                RESULTS_DIR=str(directory),
                TGEN_REQUEST_TIMEOUT="600"
                if scenario.get("suite") == "dvga-exploits"
                else "15",
            )
            result = execute(
                command,
                directory / "scenario.log",
                environment,
                scenario["timeout_seconds"],
            )
        if (
            scenario.get("fixture_contract", {}).get("family_restore")
            and not (directory / "family-restoration.json").is_file()
        ):
            family_host_action(
                directory, "restore", scenario["fixture_contract"]["family_restore"]
            )
        result["id"] = scenario["id"]
        result["source_commit"] = os.environ.get("SOURCE_COMMIT")
        result["artifact_sha256"] = os.environ.get("TGEN_ARTIFACT_SHA256")
        result["source_sha256"] = hashlib.sha256(
            (root / scenario["entrypoint"]).read_bytes()
        ).hexdigest()
        if scenario.get("fixture_contract", {}).get("restore_pastes"):
            recovery = execute(
                [
                    "python3",
                    str(root / "scripts/dvga_paste_fixture.py"),
                    "restore",
                    "https://" + os.environ["TARGET_FQDN"] + "/dvga",
                ],
                directory / "paste-recovery.log",
                environment,
                180,
            )
            result["paste_restoration"] = recovery["outcome"] == "launched"
        if scenario.get("fixture_contract", {}).get("order_restore"):
            result["order_restoration"] = restore_receipt(directory)
        await_control_evidence(scenario, result, directory, threading.Event())
        result["dispatch_contract_verified"] = False
        scenario_action_verification(directory, scenario, result)
        response_path = directory / "response-events.jsonl"
        responses = (
            [
                json.loads(line)
                for line in response_path.read_text().splitlines()
                if line.strip()
            ]
            if response_path.exists()
            else []
        )
        result["transport_failures"] = sum(
            bool(row.get("transport_error")) for row in responses
        )
        result["tool_cancellations"] = result.get("tool_cancellations", 0)
        result["functional_acceptance"] = verify_functional(
            scenario,
            result,
            attributed_responses(scenario, result, directory),
            directory,
        )
        result["functional_verified"] = result["functional_acceptance"]["passed"]
        atomic_json(directory / "receipt.json", result)
        failed |= result["outcome"] != "launched" or not result["functional_verified"]
    return int(failed)


def browser_action_receipt(directory: Path, contract: dict) -> dict:
    """Read one uniquely identified browser action receipt from the scenario directory."""
    receipts = []
    for candidate in directory.glob("*/receipt.json"):
        try:
            receipt = json.loads(candidate.read_text())
        except (OSError, ValueError):
            return {"passed": False, "reason": "browser receipt unreadable"}
        if not isinstance(receipt, dict):
            return {"passed": False, "reason": "browser receipt invalid"}
        if receipt.get("schemaVersion") == BROWSER_RECEIPT_VERSION:
            receipts.append(receipt)
    if len(receipts) != 1:
        return {"passed": False, "reason": "browser receipt missing or ambiguous"}
    return verify_browser_actions(contract, receipts[0])


def prerequisite_failure(
    identifier: str, directory: Path, state: dict, error: str
) -> dict:
    """Retain a redacted fixture failure without stopping independent catalog work."""
    result = {
        "id": identifier,
        "outcome": "fixture_failure",
        "phase": "prerequisite",
        "error": error,
        "dispatch_contract_verified": False,
        "http_requests": 0,
    }
    state["failures"] = (
        state["failures"] + [{"id": identifier, "outcome": result["outcome"]}]
    )[-200:]
    atomic_json(directory / "receipt.json", result)
    return result


def connection_action_verification(
    directory: Path, scenario: dict, result: dict
) -> None:
    """Validate a separately budgeted concrete connection probe."""
    if scenario["budget"] == "connection":
        connection_receipt = directory / "connections.json"
        if connection_receipt.exists():
            connection_data = json.loads(connection_receipt.read_text())
            result["connection_attempts"] = connection_data["attempts"]
            result["connection_limit"] = connection_data["attempt_limit_per_second"]
            result["connection_probe"] = (
                {
                    "passed": connection_data.get("passed") is True,
                    "claim": (
                        "native Masscan SYN/SYN-ACK and measured pacing"
                        if scenario.get("adapter") == "native-masscan"
                        else "named native scanner report, scoped pacing and observed process cleanup"
                    ),
                }
                if scenario.get("adapter") in ("native-masscan", "native-scanner")
                else verify_connection_probe(scenario["id"], connection_data)
            )
            result["dispatch_contract_verified"] = result["connection_probe"]["passed"]
            if (
                result["outcome"] == "launched"
                and not result["dispatch_contract_verified"]
            ):
                result["outcome"] = "tool_failure"
        else:
            result["outcome"] = "tool_failure"


def cache_action_verification(directory: Path, scenario: dict, result: dict) -> None:
    """Require cache content and isolation receipts when declared."""
    if scenario.get("adapter") == "dynamic-cache":
        evidence = directory / "cache-evidence.json"
        result["cache_evidence"] = (
            json.loads(evidence.read_text()) if evidence.exists() else {"passed": False}
        )
        result["dispatch_contract_verified"] &= (
            result["cache_evidence"].get("passed") is True
        )
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "fixture_failure"


def multiclient_action_verification(
    directory: Path, scenario: dict, result: dict
) -> None:
    """Require per-client echoed identity and cleanup evidence."""
    if scenario.get("adapter") == "bounded-multiclient":
        evidence = directory / "multiclient-evidence.json"
        result["multiclient_evidence"] = (
            json.loads(evidence.read_text()) if evidence.exists() else {"passed": False}
        )
        result["dispatch_contract_verified"] &= (
            result["multiclient_evidence"].get("passed") is True
        )
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "fixture_failure"


def nested_action_verification(directory: Path, scenario: dict, result: dict) -> None:
    """Require each declared child receipt, independent of aggregate parent traffic."""
    if "nested_contract" in scenario:
        root = Path(__file__).resolve().parents[1]
        catalog = load_catalog(root)
        digests = {
            item["id"]: hashlib.sha256(
                (root / item["entrypoint"]).read_bytes()
            ).hexdigest()
            for item in catalog["scenarios"]
        }
        reports = [
            build_report(
                directory / ("nested-" + suite),
                identifiers,
                digests,
                source_commit=result.get("source_commit"),
                artifact_sha256=result.get("artifact_sha256"),
            )
            for suite, identifiers in scenario["nested_contract"].items()
        ]
        result["nested_actions"] = reports
        result["dispatch_contract_verified"] &= bool(reports) and all(
            report["passed"] for report in reports
        )
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "tool_failure"


def fixture_action_verification(directory: Path, scenario: dict, result: dict) -> None:
    """Require mutation restoration independently of the attack response."""
    verify_restoration(directory, scenario, result)
    if scenario.get("fixture_contract", {}).get("csrf_restore"):
        evidence = directory / "csrf-restoration.json"
        restored = (
            evidence.exists()
            and json.loads(evidence.read_text()).get("restored") is True
        )
        result["csrf_restoration"] = restored
        result["dispatch_contract_verified"] &= restored
        if not restored:
            result["outcome"] = "fixture_failure"
    if scenario.get("fixture_contract", {}).get("restore_profiles"):
        evidence = directory / "fixture-restoration.json"
        result["fixture_restoration"] = (
            evidence.exists()
            and json.loads(evidence.read_text()).get("restored") is True
        )
        result["dispatch_contract_verified"] &= result["fixture_restoration"]
        if not result["fixture_restoration"]:
            result["outcome"] = "fixture_failure"


def route_action_verification(scenario: dict, result: dict) -> None:
    """Route assertions supplement dispatch and response verification."""
    if "route_contract" in scenario:
        result["dispatch_contract_verified"] = (
            result["dispatch_contract_verified"] and result["route_actions"]["passed"]
        )
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "fixture_failure"


def video_fixture_verification(directory: Path, scenario: dict, result: dict) -> None:
    """No video mutation coverage without exact fixture restoration."""
    if scenario.get("fixture_contract", {}).get("remove_disposable_videos"):
        evidence = directory / "video-deletion-cleanup.json"
        removed = (
            evidence.exists()
            and json.loads(evidence.read_text()).get("removed") is True
        )
        result["disposable_video_cleanup"] = removed
        result["dispatch_contract_verified"] &= removed
        if not removed:
            result["outcome"] = "fixture_failure"
    if scenario.get("fixture_contract", {}).get("restore_video"):
        path = directory / "video-restoration.json"
        restored = (
            path.exists() and json.loads(path.read_text()).get("restored") is True
        )
        result["video_restoration"] = restored
        result["dispatch_contract_verified"] &= restored
        if not restored:
            result["outcome"] = "fixture_failure"


def native_load_verification(directory: Path, scenario: dict, result: dict) -> None:
    """Require each native load worker to complete its real report."""
    if "native_load_contract" in scenario:
        path = directory / "native-load.json"
        result["native_load"] = (
            json.loads(path.read_text()) if path.exists() else {"passed": False}
        )
        result["dispatch_contract_verified"] &= (
            result["native_load"].get("passed") is True
        )
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "tool_failure"


def native_discovery_verification(
    directory: Path, scenario: dict, result: dict
) -> None:
    """Discovery requires real native provider results, not an HTTP filler count."""
    if scenario.get("adapter") == "native-subfinder":
        path = directory / "native-discovery.json"
        receipt = json.loads(path.read_text()) if path.exists() else {}
        result["dispatch_contract_verified"] = receipt.get("passed") is True
        result["native_discovery"] = receipt
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "tool_failure"


def scenario_action_verification(directory: Path, scenario: dict, result: dict) -> None:
    """Join actual dispatch, browser actions, and connection evidence to a launch."""
    if "tool_contract" in scenario:
        evidence = directory / "tool-events.jsonl"
        result["tool_actions"] = (
            verify_tool_actions(
                scenario["tool_contract"],
                [json.loads(line) for line in evidence.read_text().splitlines()],
            )
            if evidence.exists()
            else {"passed": False}
        )
    if "route_contract" in scenario:
        evidence = directory / "route-actions.json"
        result["route_actions"] = (
            verify_route_actions(
                scenario["route_contract"], json.loads(evidence.read_text())
            )
            if evidence.exists()
            else {"passed": False}
        )
    if "report_contract" in scenario and scenario.get("adapter") != "native-subfinder":
        evidence = directory / "report-evidence.json"
        result["dispatch_contract_verified"] = (
            evidence.exists() and json.loads(evidence.read_text()).get("passed") is True
        )
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "fixture_failure"
    if "dispatch_contract" in scenario:
        events = []
        if (directory / "dispatch-events.jsonl").exists():
            with (directory / "dispatch-events.jsonl").open() as stream:
                events = [json.loads(line) for line in stream if line.strip()]
        result["intended_dispatch"] = verify_dispatch(
            scenario["dispatch_contract"], events
        )
        result["dispatch_contract_verified"] = result["intended_dispatch"]["passed"]
        response_rows = attributed_responses(scenario, result, directory)
        result["response_assertions"] = verify_responses(
            scenario["dispatch_contract"], response_rows
        )
        result["dispatch_contract_verified"] &= result["response_assertions"]["passed"]
        if result["outcome"] == "launched" and not result["dispatch_contract_verified"]:
            result["outcome"] = "fixture_failure"
    if "browser_contract" in scenario:
        result["browser_actions"] = browser_action_receipt(
            directory, scenario["browser_contract"]
        )
        result["browser_restoration"] = result["browser_actions"]["passed"]
        result["dispatch_contract_verified"] = result["browser_actions"]["passed"] and (
            "dispatch_contract" not in scenario
            or (
                result["intended_dispatch"]["passed"]
                and result["response_assertions"]["passed"]
            )
        )
        if result["outcome"] == "launched" and not result["dispatch_contract_verified"]:
            result["outcome"] = "fixture_failure"
    if "tool_contract" in scenario:
        result["dispatch_contract_verified"] = (
            result["dispatch_contract_verified"] and result["tool_actions"]["passed"]
        )
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "tool_failure"
    route_action_verification(scenario, result)
    native_load_verification(directory, scenario, result)
    native_discovery_verification(directory, scenario, result)
    if "workload_contract" in scenario:
        evidence = directory / "workload.json"
        result["workload"] = (
            verify_workload(
                scenario["workload_contract"], json.loads(evidence.read_text())
            )
            if evidence.exists()
            else {"passed": False}
        )
        result["dispatch_contract_verified"] &= result["workload"]["passed"]
        if not result["dispatch_contract_verified"]:
            result["outcome"] = "tool_failure"
    if "scanner_contract" in scenario:
        evidence = directory / "scanner-phases.jsonl"
        result["scanner_phases"] = verify_scanner_phases(
            scenario["scanner_contract"],
            [json.loads(line) for line in evidence.read_text().splitlines()]
            if evidence.exists()
            else [],
        )
        result["dispatch_contract_verified"] &= result["scanner_phases"]["passed"]
        if not result["scanner_phases"]["passed"]:
            result["outcome"] = "tool_failure"
    video_fixture_verification(directory, scenario, result)
    native_report_verification(directory, scenario, result)
    fixture_action_verification(directory, scenario, result)
    cache_action_verification(directory, scenario, result)
    multiclient_action_verification(directory, scenario, result)
    nested_action_verification(directory, scenario, result)
    connection_action_verification(directory, scenario, result)
    result["dispatch_contract_verified"] = (
        result.get("dispatch_contract_verified", False)
        and result.get("outcome") == "launched"
    )


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
    directory = active / scenario["id"].replace("/", "--")
    directory.mkdir(mode=0o700)
    atomic_json(
        Path(config["results_dir"]) / "current-scenario.json",
        {
            "id": scenario["id"],
            "phase": "prerequisite",
            "dispatch_path": str(directory / "dispatch-events.jsonl"),
            "dispatch_contract": scenario.get("dispatch_contract", {}),
            "functional_contract": scenario.get("functional_contract", {}),
            "fixture_contract": scenario.get("fixture_contract", {}),
            "expected_statuses": scenario.get("expected_http_statuses", []),
        },
    )
    try:
        boundary.refresh_fixtures(domain, scenario.get("fixture_refresh", []))
        environment = boundary.environment(scenario, domain, directory)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        return prerequisite_failure(
            scenario["id"], directory, state, type(error).__name__
        )
    atomic_json(
        Path(config["results_dir"]) / "current-scenario.json",
        {
            "id": scenario["id"],
            "phase": "execution",
            "dispatch_path": str(directory / "dispatch-events.jsonl"),
            "dispatch_contract": scenario.get("dispatch_contract", {}),
            "functional_contract": scenario.get("functional_contract", {}),
            "fixture_contract": scenario.get("fixture_contract", {}),
            "expected_statuses": scenario.get("expected_http_statuses", []),
        },
    )
    if scenario.get("fixture_contract", {}).get(
        "order_restore"
    ) and not boundary.order_fixture(directory, "prepare"):
        return prerequisite_failure(
            scenario["id"], directory, state, "order journal snapshot failed"
        )
    before = boundary.metrics()
    command = boundary.wrap(
        scenario_command(root, scenario, domain),
        connection=scenario["budget"] == "connection"
        or scenario["id"] == "reconnaissance/05-subfinder-enum",
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
            "source_commit": config["source_commit"],
            "artifact_sha256": config["artifact_sha256"],
            "source_sha256": hashlib.sha256(
                (root / scenario["entrypoint"]).read_bytes()
            ).hexdigest(),
            "http_requests": after.get("scenario_requests", 0)
            - before.get("scenario_requests", 0),
            "claim": scenario["expected_outcome"],
            "dispatch_contract_verified": False,
        }
    )
    await_control_evidence(scenario, result, directory, stop)
    scenario_action_verification(directory, scenario, result)
    response_path = directory / "response-events.jsonl"
    responses = (
        [
            json.loads(line)
            for line in response_path.read_text().splitlines()
            if line.strip()
        ]
        if response_path.exists()
        else []
    )
    result["mitigated_requests"] = sum(
        event.get("scenario") == scenario["id"]
        and event.get("kind") == "scenario"
        and event.get("status") in (403, 429)
        and event.get("outcome") != "expected_application_rejection"
        for event in responses
    )
    result["application_rejections"] = sum(
        event.get("scenario") == scenario["id"]
        and event.get("kind") == "scenario"
        and event.get("outcome") == "expected_application_rejection"
        for event in responses
    )
    result["transport_failures"] = after.get(
        "scenario_transport_failures", 0
    ) - before.get("scenario_transport_failures", 0)
    result["tool_cancellations"] = after.get("tool_cancellations", 0) - before.get(
        "tool_cancellations", 0
    )
    if result["tool_cancellations"] and result["outcome"] in (
        "launched",
        "fixture_failure",
    ):
        result["outcome"] = "tool_failure"
    if scenario["kind"] == "javascript":
        log_text = (directory / "scenario.log").read_text(errors="replace")
        if re.search(
            r"(?m)^\s*(Registrations attempted|Contact forms submitted): 0$", log_text
        ):
            result["outcome"] = "fixture_failure"
    if result["outcome"] == "launched" and result["transport_failures"]:
        result["outcome"] = "transport_failure"
    if (
        result["outcome"] == "launched"
        and scenario["budget"] == "http"
        and result["http_requests"] == 0
    ):
        result["outcome"] = "fixture_failure"
    recover_fixtures(boundary, scenario, result, directory, domain, environment)
    result["functional_acceptance"] = verify_functional(
        scenario, result, attributed_responses(scenario, result, directory), directory
    )
    result["functional_verified"] = result["functional_acceptance"]["passed"]
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
            if not boundary.healthy():
                state["failures"] = (
                    state["failures"]
                    + [
                        {
                            "id": state.get("current_scenario"),
                            "outcome": "proxy_failure",
                        }
                    ]
                )[-200:]
                stop.set()
                break
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
            state["traffic_before"] = boundary.metrics()
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
            receipt = current_pass_receipt(
                root,
                scenarios,
                state["pass_started"],
                active,
                receipts,
                config,
                pass_traffic(state["traffic_before"], boundary.metrics()),
            )
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
    return (
        0
        if not state["failures"]
        and (
            continuous or state.get("last_pass", {}).get("functional_verified") is True
        )
        else 1
    )


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
