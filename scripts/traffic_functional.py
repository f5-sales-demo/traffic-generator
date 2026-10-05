"""Functional acceptance from source contracts and observed native responses."""

import base64
import hashlib
import json
from itertools import pairwise
from pathlib import Path

from traffic_csd_functional import verify_csd_libraries
from traffic_dispatch import verify_browser_actions
from traffic_report import build_report
from traffic_security import bot_attribution

CREDENTIAL_COUNT = 15
CONNECTION_LIMIT = 20
MIN_RESOURCE_SAMPLES = 2
SHA256_LENGTH = 64
HTTP_OK = 200
VIDEO_ATTEMPTS = 4
HTTP_NOT_FOUND = 404
SOURCE_ROOT = Path(__file__).resolve().parents[1]


def verify_credentials(scenario: dict, result: dict, directory: Path) -> dict:
    """Inspect native browser outcomes, exact credential count, and closed sessions."""
    path = directory / "credential-functional.json"
    try:
        evidence = json.loads(path.read_text()) if path.exists() else {}
    except (OSError, ValueError):
        return {"passed": False, "reason": "native credential evidence unreadable"}
    if not isinstance(evidence, dict):
        return {
            "passed": False,
            "reason": "native credential evidence is not an object",
        }
    attempts = evidence.get("attempts", [])
    if not isinstance(attempts, list) or any(not isinstance(a, dict) for a in attempts):
        return {"passed": False, "reason": "native credential attempts malformed"}
    screenshots = evidence.get("screenshots", [])
    if not isinstance(screenshots, list) or any(
        not isinstance(name, str) for name in screenshots
    ):
        return {"passed": False, "reason": "native credential screenshots malformed"}
    passed = (
        evidence.get("scenario") == scenario["id"]
        and evidence.get("source_commit") == result.get("source_commit")
        and evidence.get("passed") is True
        and evidence.get("contextsClosed") is True
        and evidence.get("browserErrors") == []
        and len(attempts) == CREDENTIAL_COUNT
        and [attempt.get("index") for attempt in attempts]
        == list(range(CREDENTIAL_COUNT))
        and all(
            attempt.get("passed") is True
            and attempt.get("sessionClosed") is True
            and attempt.get("expectedAccepted") is (attempt["index"] == 0)
            and (
                attempt.get("accepted") is True
                if attempt["index"] == 0
                else attempt.get("rejected") is True
            )
            for attempt in attempts
        )
        and len(evidence.get("screenshots", [])) == CREDENTIAL_COUNT
        and all(
            Path(name).name == name
            and (directory / name).is_file()
            and (directory / name)
            .read_bytes()
            .startswith(bytes.fromhex("89504e470d0a1a0a"))
            for name in evidence.get("screenshots", [])
        )
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0
    )
    return {
        "passed": passed,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_attempts": len(attempts),
        "screenshots": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in evidence.get("screenshots", [])
            if Path(name).name == name and (directory / name).is_file()
        },
        "evidence": path.name,
        "control_attribution": "separate WAAP evidence required",
    }


def verify_slow_headers(scenario: dict, result: dict, directory: Path) -> dict:
    """Require paced native partial headers, observed rounds, and closed sockets."""
    path = directory / "connections.json"
    receipt = json.loads(path.read_text()) if path.exists() else {}
    probes = receipt.get("results", [])
    attempts = [probe.get("attempted_monotonic") for probe in probes]
    rate = receipt.get("attempt_limit_per_second", 0)
    spacing = (
        0 < rate <= CONNECTION_LIMIT
        and bool(attempts)
        and all(isinstance(value, (int, float)) for value in attempts)
    )
    spacing = spacing and all(
        later - earlier >= 1 / rate - 0.001 for earlier, later in pairwise(attempts)
    )
    return {
        "passed": receipt.get("execution") == "native-openssl-slow-headers"
        and receipt.get("scenario") == scenario["id"]
        and spacing
        and all(probe.get("partial_headers_sent") is True for probe in probes)
        and result.get("connection_probe", {}).get("passed") is True
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "observed_attempt_spacing": spacing,
        "claim": "native slow-header connection behavior; control attribution separate",
    }


def verify_commands(scenario: dict, result: dict, directory: Path) -> dict:
    """Require every declared native command response, not only payload dispatch."""
    path = directory / "command-functional.jsonl"
    rows = (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )
    required = len(scenario["dispatch_contract"]["requirements"])
    return {
        "passed": len(rows) == required
        and all(row.get("passed") is True for row in rows)
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_outcomes": len(rows),
        "control_attribution": "separate WAAP evidence required",
    }


def verify_otp(scenario: dict, result: dict, directory: Path) -> dict:
    """Require native guess outcomes and independent isolated actor restoration."""
    evidence = json.loads((directory / "otp-functional.json").read_text())
    return {
        "passed": evidence.get("passed") is True
        and evidence.get("source_commit") == result.get("source_commit")
        and evidence.get("artifact_sha256") == result.get("artifact_sha256")
        and result.get("otp_restoration") is True
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_attempts": len(evidence.get("attempts", [])),
    }


def verify_native_contract(scenario: dict, result: dict, directory: Path) -> dict:
    """Select the real native contract evidence without substituting probe behavior."""
    contract = scenario["functional_contract"]
    if contract["verifier"] == "native-crapi-otp":
        return verify_otp(scenario, result, directory)
    receipt = json.loads((directory / "connections.json").read_text())
    return {
        "passed": receipt.get("passed") is True
        and receipt.get("source_commit") == result.get("source_commit")
        and receipt.get("artifact_sha256") == result.get("artifact_sha256")
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True,
        "behavior": contract["behavior"],
        "native_report_verified": True,
    }


def verify_video_conversion(
    scenario: dict, result: dict, responses: list[dict], directory: Path
) -> dict:
    """Require native conversion phases and exact media/name/parameter recovery."""
    before = json.loads((directory / "crapi-video-snapshot.json").read_text())
    recovery = json.loads((directory / "video-restoration.json").read_text())
    expected = {
        "id": before["id"],
        "video_name": before["video_name"],
        "conversion_params": before["conversion_params"],
        "media_sha256": hashlib.sha256(
            base64.b64decode(before["profileVideo"].split(",", 1)[1])
        ).hexdigest(),
    }
    checks = []
    for requirement in scenario["dispatch_contract"]["requirements"]:
        rows = [
            r
            for r in responses
            if requirement["id"] in r.get("matched_requirements", [])
            and r.get("kind") == "scenario"
        ]
        checks.append(
            len(rows) >= requirement["minimum_dispatches"]
            and all(
                r.get("upstream_dispatched") is True
                and not r.get("transport_error")
                and r.get("response_assertions", {}).get(requirement["id"]) is True
                and r.get("status") in requirement["expected_statuses"]
                for r in rows
            )
        )
    return {
        "passed": all(checks)
        and bool(checks)
        and recovery.get("before") == recovery.get("after") == expected
        and recovery.get("restored") is True
        and result.get("video_restoration") is True
        and recovery.get("source_commit") == result.get("source_commit")
        and recovery.get("artifact_sha256") == result.get("artifact_sha256")
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "claim": "native parameter updates and conversion protocol outcomes; no inferred command execution",
    }


def verify_video_deletion(scenario: dict, result: dict, directory: Path) -> dict:
    """Require four actual owned uploads, regular-user delete outcomes and native absence."""
    evidence = json.loads((directory / "video-deletion-cleanup.json").read_text())
    objects = evidence.get("objects", [])
    return {
        "passed": evidence.get("removed") is True
        and evidence.get("owned_uploads") == VIDEO_ATTEMPTS
        and len(objects) == VIDEO_ATTEMPTS
        and {row.get("attempt") for row in objects} == {1, 2, 3, 4}
        and all(
            isinstance(row.get("video_id"), int)
            and row["video_id"] > 0
            and row.get("upload_status") in (200, 201)
            and row.get("delete_status") in (200, 204)
            and row.get("absent_status") == HTTP_NOT_FOUND
            for row in objects
        )
        and evidence.get("source_commit") == result.get("source_commit")
        and evidence.get("artifact_sha256") == result.get("artifact_sha256")
        and result.get("disposable_video_cleanup") is True
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "owned_uploads": len(objects),
    }


def verify_csrf(scenario: dict, result: dict, directory: Path) -> dict:
    """Require actual isolated password mutation, fresh authentication and recovery."""
    evidence = json.loads((directory / "csrf-restoration.json").read_text())
    return {
        "passed": evidence.get("actor") == "tgen_csrf"
        and evidence.get("changed") is True
        and evidence.get("fresh_login") is True
        and evidence.get("restored") is True
        and evidence.get("source_commit") == result.get("source_commit")
        and evidence.get("artifact_sha256") == result.get("artifact_sha256")
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
    }


def verify_role_mutation(scenario: dict, result: dict, directory: Path) -> dict:
    """Require every actual role payload readback and exact original profile restoration."""
    before = json.loads((directory / "restaurant-role-snapshot.json").read_text())
    recovery = json.loads((directory / "fixture-restoration.json").read_text())
    rows = [
        json.loads(line)
        for line in (directory / "role-native-outcomes.jsonl").read_text().splitlines()
    ]
    expected = {
        "role-0": "Chef",
        "role-1": "Chef",
        "role-2": "Chef",
        "role-3": "Chef",
        "role-4": "Chef",
        "role-5": "Chef",
    }
    return {
        "passed": before.get("username", "").startswith("tgen_bola_")
        and len(rows) == len(expected)
        and {row.get("id") for row in rows} == set(expected)
        and all(
            row.get("profile", {}).get("username") == before["username"]
            and row["profile"].get("role") == expected[row["id"]]
            and row.get("source_commit") == result.get("source_commit")
            and row.get("artifact_sha256") == result.get("artifact_sha256")
            for row in rows
        )
        and recovery.get("before") == recovery.get("after") == before
        and recovery.get("restored") is True
        and recovery.get("source_commit") == result.get("source_commit")
        and recovery.get("artifact_sha256") == result.get("artifact_sha256")
        and result.get("fixture_restoration") is True
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_payloads": len(rows),
    }


def verify_profile_restoration(scenario: dict, result: dict, directory: Path) -> bool:
    """Require exact actor snapshot and native after-readback coverage."""
    try:
        before = [
            json.loads(line)
            for line in (directory / "restaurant-profile-snapshot.jsonl")
            .read_text()
            .splitlines()
        ]
        receipt = json.loads((directory / "fixture-restoration.json").read_text())
        actors = receipt.get("actors", [])
        required = scenario["functional_contract"]["profile_actors"]
        return (
            receipt.get("restored") is True
            and receipt.get("source_commit") == result.get("source_commit")
            and receipt.get("artifact_sha256") == result.get("artifact_sha256")
            and len(before) == len(actors) == len(required)
            and {row.get("actor") for row in before} == set(required)
            and {row.get("before", {}).get("actor") for row in actors} == set(required)
            and all(
                row.get("before") in before
                and row.get("after", {}).get("username") == row["before"]["username"]
                and row.get("after", {}).get("phone_number")
                == row["before"]["phone_number"]
                for row in actors
            )
        )
    except (OSError, ValueError, KeyError, TypeError):
        return False


def verify_composed_native(
    scenario: dict, result: dict, responses: list[dict], directory: Path
) -> dict:
    """Require declared native protocol content plus each specialized tool/fixture gate."""
    requirements = scenario.get("dispatch_contract", {}).get("requirements", [])
    checks = []
    for requirement in requirements:
        rows = [
            r
            for r in responses
            if r.get("kind") == "scenario"
            and r.get("scenario") == scenario["id"]
            and requirement["id"] in r.get("matched_requirements", [])
        ]
        checks.append(
            {
                "id": requirement["id"],
                "passed": len(rows) >= requirement.get("minimum_dispatches", 1)
                and all(
                    r.get("upstream_dispatched") is True
                    and r.get("native_response_identity") is True
                    and r.get("status") in requirement.get("expected_statuses", [])
                    and (
                        "response_contract" not in requirement
                        or r.get("response_assertions", {}).get(requirement["id"])
                        is True
                    )
                    and (
                        r.get("status") not in (403, 429)
                        or r.get("status_specific_assertions", {}).get(
                            requirement["id"]
                        )
                        is True
                    )
                    and not r.get("transport_error")
                    for r in rows
                ),
            }
        )
    for field in [
        "tool_actions",
        "route_actions",
        "native_load",
        "native_reports",
        "workload",
        "scanner_phases",
        "cache_evidence",
        "multiclient_evidence",
    ]:
        if field in result:
            checks.append({"id": field, "passed": result[field].get("passed") is True})  # noqa: PERF401
    for field in [
        "fixture_restoration",
        "video_restoration",
        "disposable_video_cleanup",
        "otp_restoration",
    ]:
        if field in result:
            checks.append({"id": field, "passed": result[field] is True})  # noqa: PERF401
    if scenario["functional_contract"].get("profile_actors"):
        checks.append(
            {
                "id": "profile-native-readback",
                "passed": verify_profile_restoration(scenario, result, directory),
            }
        )
    mutation = scenario["functional_contract"].get("mutation_policy")
    if mutation not in ("read-only", "journaled-restoration"):
        return {"passed": False, "reason": "mutation recovery contract missing"}
    recovery_fields = scenario["functional_contract"].get("restoration_fields", [])
    if mutation == "journaled-restoration" and (
        not recovery_fields
        or not all(
            field
            in (
                "fixture_restoration",
                "video_restoration",
                "disposable_video_cleanup",
                "otp_restoration",
                "signup_restoration",
            )
            and result.get(field) is True
            for field in recovery_fields
        )
    ):
        return {"passed": False, "reason": "observed mutation recovery missing"}
    return {
        "passed": bool(checks)
        and all(c["passed"] for c in checks)
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "checks": checks,
        "control_attribution": "separate request-bound WAAP event evidence required",
    }


def verify_load(scenario: dict, result: dict, directory: Path) -> dict:
    """Require every declared native load combination, reports, content and cleanup."""
    contract = scenario["native_load_contract"]
    receipt = json.loads((directory / "native-load.json").read_text())
    workers = receipt.get("workers", [])
    required = {
        (tool, path, level, persistent)
        for tool in contract["tools"]
        for path in contract["paths"]
        for level in contract["levels"]
        for persistent in contract["connection_modes"]
    }
    observed = {
        (w.get("tool"), w.get("path"), w.get("concurrency"), w.get("persistent"))
        for w in workers
    }
    content = receipt.get("content_checks", [])
    passed = (
        required <= observed
        and receipt.get("passed") is True
        and receipt.get("cleanup") is True
    )
    passed = passed and bool(content) and all(c.get("passed") is True for c in content)
    if contract.get("lua_script"):
        passed = passed and any(w.get("lua_sha256") for w in workers)
    if contract.get("resource_profile"):
        passed = (
            passed and len(receipt.get("resource_samples", [])) >= MIN_RESOURCE_SAMPLES
        )
    return {
        "passed": passed
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_workers": len(workers),
        "application_content": bool(content),
    }


def verify_display_browser(scenario: dict, result: dict, directory: Path) -> dict:
    """Require actual browser steps, screenshot digests and cleanup; CSD is display-only."""
    files = list(directory.glob("*/receipt.json"))
    if len(files) != 1:
        return {"passed": False, "reason": "unique browser receipt required"}
    receipt = json.loads(files[0].read_text())
    actions = verify_browser_actions(scenario["browser_contract"], receipt)
    images = []
    for native in receipt.get("scenarios", []):
        if native.get("name") != scenario["scenario"]:
            continue
        for step in native.get("steps", []):
            image = step.get("screenshot", {})
            name = image.get("path", "")
            file = files[0].parent / name
            images.append(
                bool(name)
                and Path(name).name == name
                and file.is_file()
                and hashlib.sha256(file.read_bytes()).hexdigest() == image.get("sha256")
            )
    return {
        "passed": actions["passed"]
        and bool(images)
        and all(images)
        and receipt.get("runtime", {}).get("csdEnabled") is False
        and receipt.get("runtime", {}).get("sourceCommit")
        == result.get("source_commit")
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True,
        "behavior": scenario["functional_contract"]["behavior"],
        "claim": "display only; no CSD mitigation",
    }


def verify_scraper(scenario: dict, result: dict, directory: Path) -> dict:
    """Require native content and screenshots for every declared scraped page."""
    evidence = json.loads((directory / "scraper-functional.json").read_text())
    actions = evidence.get("actions", [])
    required = scenario["scrape_contract"]["paths"]
    return {
        "passed": len(actions) == len(required)
        and {a.get("path") for a in actions} == set(required)
        and evidence.get("scenario") == scenario["id"]
        and evidence.get("source_commit") == result.get("source_commit")
        and evidence.get("artifact_sha256") == result.get("artifact_sha256")
        and evidence.get("browser_closed") is True
        and all(
            a.get("passed") is True
            and a.get("content_matches") is True
            and a.get("status") == HTTP_OK
            and len(a.get("response_sha256", "")) == SHA256_LENGTH
            and Path(a.get("screenshot", "")).name == a.get("screenshot")
            and (directory / a["screenshot"]).is_file()
            and (directory / a["screenshot"])
            .read_bytes()
            .startswith(bytes.fromhex("89504e470d0a1a0a"))
            for a in actions
        )
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0,
        "behavior": scenario["functional_contract"]["behavior"],
        "native_pages": len(actions),
    }


def verify_native_routes(scenario: dict, result: dict, directory: Path) -> dict:
    """Require each real rendered route, image bytes, source binding and browser cleanup."""
    receipt = json.loads((directory / "route-actions.json").read_text())
    required = scenario["route_contract"]["actions"]
    actions = receipt.get("actions", [])
    images = {identifier: directory / (identifier + ".png") for identifier in required}
    control_path = directory / "control-attribution.json"
    controls = (
        json.loads(control_path.read_text()).get("checks", [])
        if control_path.is_file() and not control_path.is_symlink()
        else []
    )
    passed = (
        len(actions) == len(required)
        and {item.get("id") for item in actions} == set(required)
        and receipt.get("scenario") == scenario["id"]
        and receipt.get("source_commit") == result.get("source_commit")
        and receipt.get("artifact_sha256") == result.get("artifact_sha256")
        and receipt.get("browser_closed") is True
        and all(
            (
                item.get("performed") is True
                and item.get("rendered") is True
                and item.get("contentMatches") is True
                and item.get("urlMatches") is True
                and item.get("status") not in (403, 429)
            )
            or any(
                check.get("action_id") == item.get("id")
                and bot_attribution(item, check.get("response", {}), result, directory)
                for check in controls
            )
            for item in actions
        )
        and all(
            file.is_file()
            and file.read_bytes().startswith(bytes.fromhex("89504e470d0a1a0a"))
            for file in images.values()
        )
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and result.get("transport_failures") == 0
        and result.get("tool_cancellations") == 0
    )
    return {
        "passed": passed,
        "behavior": scenario["functional_contract"]["behavior"],
        "rendered_actions": len(actions),
        "screenshot_sha256": {
            identifier: hashlib.sha256(file.read_bytes()).hexdigest()
            for identifier, file in images.items()
            if file.is_file()
        },
        "control_attribution": "native routes or request-bound WAF bot blocks; unattributed denials fail",
    }


def verify_discovery(scenario: dict, result: dict, directory: Path) -> dict:
    """Read real passive discovery rows and require source-bound native process cleanup."""
    evidence = json.loads((directory / "native-discovery.json").read_text())
    report = (directory / "subfinder-native.jsonl").read_bytes()
    rows = [json.loads(line) for line in report.splitlines() if line.strip()]
    process = evidence.get("process", {})
    domain = evidence.get("authorized_domain", "")
    return {
        "passed": bool(domain)
        and bool(rows)
        and evidence.get("passed") is True
        and evidence.get("scenario") == scenario["id"]
        and evidence.get("execution") == "native-subfinder"
        and evidence.get("source_commit") == result.get("source_commit")
        and evidence.get("artifact_sha256") == result.get("artifact_sha256")
        and evidence.get("report_sha256") == hashlib.sha256(report).hexdigest()
        and len(evidence.get("binary_sha256", "")) == SHA256_LENGTH
        and len(rows) == evidence.get("discoveries")
        and all(
            isinstance(row, dict)
            and row.get("host", "").endswith("." + domain)
            and row.get("source")
            for row in rows
        )
        and process.get("exit_code") == 0
        and process.get("timed_out") is False
        and process.get("observed_process_count", 0) > 0
        and process.get("connections_closed") is True
        and process.get("remaining_after_cleanup") == []
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True,
        "behavior": scenario["functional_contract"]["behavior"],
        "claim": "passive native discovery only; discovered hosts never scanned",
    }


def verify_current_report(scenario: dict, result: dict, directory: Path) -> dict:
    """Recompute current-pass dependencies against installed source and artifact bytes."""
    dependencies = scenario["report_contract"]["dependencies"]
    catalog = json.loads((SOURCE_ROOT / "suites/catalog.json").read_text())
    digests = {
        item["id"]: hashlib.sha256(
            (SOURCE_ROOT / item["entrypoint"]).read_bytes()
        ).hexdigest()
        for item in catalog["scenarios"]
        if item["id"] in dependencies
    }
    report = build_report(
        directory.parent,
        dependencies,
        digests,
        source_commit=result.get("source_commit"),
        artifact_sha256=result.get("artifact_sha256"),
    )
    return {
        "passed": report["passed"]
        and result.get("outcome") == "launched"
        and result.get("dispatch_contract_verified") is True
        and bool(result.get("source_commit"))
        and bool(result.get("artifact_sha256")),
        "behavior": scenario["functional_contract"]["behavior"],
        "dependencies": report["dependencies"],
        "claim": "current-pass native outcomes; no inferred exploit or control success",
    }


def verify_functional(  # noqa: PLR0911  # pylint: disable=too-many-return-statements
    scenario: dict, result: dict, responses: list[dict], directory: Path
) -> dict:
    """Require explicit scope, content assertions, and complete native outcomes."""
    contract = scenario.get("functional_contract", {})
    specialized = {
        "native-video-deletion": verify_video_deletion,
        "native-dvwa-csrf": verify_csrf,
        "native-role-mutation": verify_role_mutation,
        "native-scraper": verify_scraper,
        "native-browser-routes": verify_native_routes,
        "native-subfinder": verify_discovery,
        "current-pass-report": verify_current_report,
        "native-browser-display": verify_display_browser,
        "native-load": verify_load,
    }
    if contract.get("verifier") in specialized:
        return specialized[contract["verifier"]](scenario, result, directory)
    if contract.get("verifier") == "native-video-conversion":
        return verify_video_conversion(scenario, result, responses, directory)
    if contract.get("verifier") == "composed-native":
        return verify_composed_native(scenario, result, responses, directory)
    if contract.get("verifier") == "native-crapi-signup":
        evidence = json.loads((directory / "signup-functional.json").read_text())
        path = directory / "fixture-recovery-receipt.json"
        recovery = json.loads(path.read_text()) if path.exists() else {"passed": False}
        return {
            "passed": evidence.get("passed") is True
            and recovery.get("passed") is True
            and evidence.get("source_commit") == result.get("source_commit")
            and evidence.get("artifact_sha256") == result.get("artifact_sha256")
            and result.get("outcome") == "launched"
            and result.get("dispatch_contract_verified") is True,
            "behavior": contract["behavior"],
            "exact_signup_recovery": recovery.get("passed") is True,
        }

    if (
        contract.get("verifier") == "native-dvwa-credentials"
        and scenario["id"] == "bot-simulation/01-playwright-credential-stuff"
    ):
        return verify_credentials(scenario, result, directory)
    if contract.get("verifier") == "native-csd-libraries":
        return verify_csd_libraries(scenario, result, directory)
    if (
        contract.get("verifier") == "native-slow-headers"
        and scenario["id"] == "traffic-generation/02-slowloris"
    ):
        return verify_slow_headers(scenario, result, directory)
    if (
        contract.get("verifier") == "native-dvwa-command"
        and scenario["id"] == "dvwa-exploits/02-command-injection"
    ):
        return verify_commands(scenario, result, directory)
    if contract.get("verifier") in (
        "native-masscan",
        "native-scanner",
        "native-crapi-otp",
    ):
        return verify_native_contract(scenario, result, directory)
    requirements = scenario.get("dispatch_contract", {}).get("requirements", [])
    declared = contract.get("native_response_requirements", [])
    checks = [
        {
            "id": "direct-native-api",
            "passed": scenario.get("kind") == "shell"
            and not scenario.get("adapter")
            and not any(
                key in scenario
                for key in (
                    "tool_contract",
                    "nested_contract",
                    "workload_contract",
                    "browser_contract",
                    "fixture_contract",
                )
            ),
        },
        {"id": "declared-functional-scope", "passed": bool(contract.get("behavior"))},
        {
            "id": "read-only-scope",
            "passed": contract.get("mutation_policy") == "read-only"
            and bool(requirements)
            and all(r["method"] in ("GET", "HEAD") for r in requirements),
        },
        {
            "id": "complete-action-contract",
            "passed": bool(declared)
            and set(declared) == {r["id"] for r in requirements},
        },
        {
            "id": "successful-execution",
            "passed": result.get("outcome") == "launched"
            and result.get("dispatch_contract_verified") is True,
        },
        {
            "id": "zero-transport-failures",
            "passed": result.get("transport_failures") == 0
            and result.get("tool_cancellations") == 0,
        },
    ]
    for requirement in requirements:
        identifier = requirement["id"]
        events = [
            e
            for e in responses
            if e.get("scenario") == scenario["id"]
            and e.get("kind") == "scenario"
            and identifier in e.get("matched_requirements", [])
        ]
        specification = requirement.get("response_contract", {})
        content_declared = bool(specification.get("content_type")) and any(
            specification.get(key)
            for key in (
                "text_contains",
                "json_equals",
                "json_keys",
                "json_nonempty_lists",
                "json_document_equals",
                "graphql_data_field",
                "graphql_response_fields",
            )
        )
        checks.append(
            {
                "id": identifier,
                "observed": len(events),
                "passed": identifier in declared
                and content_declared
                and len(events) >= requirement.get("minimum_dispatches", 1)
                and all(
                    e.get("upstream_dispatched") is True
                    and not e.get("transport_error")
                    and e.get("status") in requirement.get("expected_statuses", [])
                    and e.get("response_assertions", {}).get(identifier) is True
                    for e in events
                ),
            }
        )
    return {
        "passed": all(check["passed"] for check in checks),
        "behavior": contract.get("behavior"),
        "checks": checks,
        "control_attribution": "separate WAAP evidence required",
    }
