"""Validate supplied private control evidence against each actual native request."""

import json
import time
from datetime import datetime
from pathlib import Path
from threading import Event

from traffic_common import atomic_json

FORBIDDEN = 403
PAIR_LENGTH = 2
MAX_CLOCK_OFFSET = 5
SHA256_LENGTH = 64
MAX_EVENT_RECORDING_DELAY_SECONDS = 20
RESPONSE_IDENTITY_FIELDS = (
    "scenario",
    "domain",
    "path",
    "method",
    "status",
    "synthetic_identity",
    "sent_at",
    "received_at",
    "payload_sha256",
    "response_sha256",
)


def request_identity(row: dict) -> tuple:
    """Use complete response receipt identity rather than path or status alone."""
    return tuple(row.get(key) for key in RESPONSE_IDENTITY_FIELDS)


def joined(
    record: dict, response: dict, scope: dict, bounds: list, delay: int = 0
) -> bool:
    """Require scope, request identity, response status and calibrated time."""
    try:
        if (
            not isinstance(delay, int)
            or isinstance(delay, bool)
            or not 0 <= delay <= MAX_EVENT_RECORDING_DELAY_SECONDS
        ):
            return False
        if not str(response.get("synthetic_identity", "")).endswith("-request"):
            delay = 0
        moment = datetime.fromisoformat(record["time"]).timestamp()
        return (
            response["sent_at"] + bounds[0]
            <= moment
            <= response["received_at"] + bounds[1] + delay
            and record.get("namespace") == scope["namespace"]
            and record.get("vh_name")
            == "ves-io-http-loadbalancer-" + scope["loadbalancer"]
            and record.get("domain") == response["domain"] == scope["domain"]
            and record.get("req_path") == response["path"]
            and record.get("method") == response["method"]
            and record.get("user")
            == "Header-X-Mud-User-" + response["synthetic_identity"]
            and str(record.get("rsp_code")) == str(response["status"])
        )
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def security_request_id(
    check: dict, response: dict, scope: dict, bounds: list, delay: int = 0
) -> str | None:
    """Bind an actual security record; sampled-out access stays absent."""
    request_id = check.get("security_request_id")
    access = check.get("access")
    if access is not None:
        if (
            not isinstance(access, dict)
            or not access.get("req_id")
            or not joined(access, response, scope, bounds, delay)
        ):
            return None
        if request_id is not None and request_id != access["req_id"]:
            return None
        return access["req_id"]
    if not request_id or not str(response.get("synthetic_identity", "")).endswith(
        "-request"
    ):
        return None
    candidates = {
        event.get("req_id")
        for event in check.get("events", [])
        if joined(event, response, scope, bounds, delay)
    }
    return request_id if candidates == {request_id} else None


def bot_attribution(
    action: dict, response: dict, result: dict, directory: Path
) -> bool:
    """Accept search-engine impersonation only with actual WAF bot block attribution."""
    path = directory / "control-attribution.json"
    if not path.is_file() or path.is_symlink():
        return False
    try:
        evidence = json.loads(path.read_text())
        scope = evidence["scope"]
        bounds = evidence["clock_bounds"]
        firewall = evidence["firewall"]
        if not (
            all(key in response for key in RESPONSE_IDENTITY_FIELDS)
            and len(response.get("payload_sha256", "")) == SHA256_LENGTH
            and len(response.get("response_sha256", "")) == SHA256_LENGTH
            and evidence.get("source_commit") == result.get("source_commit")
            and evidence.get("artifact_sha256") == result.get("artifact_sha256")
            and action.get("fresh_document_response") is True
            and action.get("performed") is True
            and action.get("mitigated") is True
            and response.get("upstream_dispatched") is True
            and response.get("status") == FORBIDDEN
            and firewall.get("metadata", {}).get("name")
            == scope["loadbalancer"] + "-waf"
            and firewall.get("metadata", {}).get("namespace") == scope["namespace"]
            and "blocking" in firewall["spec"]
            and "monitoring" not in firewall["spec"]
            and "default_bot_setting" in firewall["spec"]
            and len(bounds) == PAIR_LENGTH
            and -MAX_CLOCK_OFFSET <= bounds[0] <= bounds[1] <= MAX_CLOCK_OFFSET
        ):
            return False
        checks = [
            c
            for c in evidence["checks"]
            if c.get("action_id") == action["id"]
            and request_identity(c["response"]) == request_identity(response)
        ]
        if len(checks) != 1:
            return False
        request_id = security_request_id(
            checks[0],
            response,
            scope,
            bounds,
            evidence.get("event_recording_delay_seconds", 0),
        )
        if request_id is None:
            return False
        return any(
            event.get("req_id") == request_id
            and joined(
                event,
                response,
                scope,
                bounds,
                evidence.get("event_recording_delay_seconds", 0),
            )
            and event.get("action") == "block"
            and event.get("sec_event_type") == "waf_sec_event"
            and event.get("sec_event_name") == "WAF"
            and event.get("app_firewall_name") == scope["loadbalancer"] + "-waf"
            and event.get("enforcement_mode") == "Blocking"
            and event.get("waf_mode") == "block"
            and event.get("recommended_action") == "block"
            and event.get("bot_info", {}).get("classification") == "malicious"
            and event.get("bot_info", {}).get("anomaly")
            == "Search Engine Verification Failed"
            and event.get("bot_info", {}).get("type") == "Search Engine"
            and event.get("bot_info", {}).get("name") in ("Google", "Bing")
            for event in checks[0]["events"]
        )
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False


def waf_attribution(
    response: dict, result: dict, directory: Path, signatures: list[str]
) -> bool:
    """Require actual request-bound enabled WAF signature and effective blocking configuration."""
    path = directory / "control-attribution.json"
    if not path.is_file() or path.is_symlink():
        return False
    try:
        evidence = json.loads(path.read_text())
        scope = evidence["scope"]
        bounds = evidence["clock_bounds"]
        firewall = evidence["firewall"]
        if not (
            all(key in response for key in RESPONSE_IDENTITY_FIELDS)
            and len(response.get("payload_sha256", "")) == SHA256_LENGTH
            and len(response.get("response_sha256", "")) == SHA256_LENGTH
            and evidence.get("source_commit") == result.get("source_commit")
            and evidence.get("artifact_sha256") == result.get("artifact_sha256")
            and response.get("upstream_dispatched") is True
            and response.get("status") == FORBIDDEN
            and firewall.get("metadata", {}).get("name")
            == scope["loadbalancer"] + "-waf"
            and firewall.get("metadata", {}).get("namespace") == scope["namespace"]
            and "blocking" in firewall["spec"]
            and "monitoring" not in firewall["spec"]
            and len(bounds) == PAIR_LENGTH
            and -MAX_CLOCK_OFFSET <= bounds[0] <= bounds[1] <= MAX_CLOCK_OFFSET
        ):
            return False
        checks = [
            c
            for c in evidence["checks"]
            if request_identity(c["response"]) == request_identity(response)
        ]
        if len(checks) != 1:
            return False
        request_id = security_request_id(
            checks[0],
            response,
            scope,
            bounds,
            evidence.get("event_recording_delay_seconds", 0),
        )
        if request_id is None:
            return False
        return any(
            event.get("req_id") == request_id
            and joined(
                event,
                response,
                scope,
                bounds,
                evidence.get("event_recording_delay_seconds", 0),
            )
            and event.get("action") == "block"
            and event.get("sec_event_type") == "waf_sec_event"
            and event.get("sec_event_name") == "WAF"
            and event.get("app_firewall_name") == scope["loadbalancer"] + "-waf"
            and event.get("enforcement_mode") == "Blocking"
            and event.get("waf_mode") == "block"
            and event.get("recommended_action") == "block"
            and (
                any(
                    (not signatures or str(sig.get("id")) in signatures)
                    and sig.get("state") == "Enabled"
                    for sig in event.get("signatures", [])
                )
                or (
                    not signatures
                    and "default_bot_setting" in firewall["spec"]
                    and event.get("bot_info", {}).get("classification") == "malicious"
                    and isinstance(event.get("bot_info", {}).get("name"), str)
                    and bool(event["bot_info"]["name"])
                    and isinstance(event.get("bot_info", {}).get("type"), str)
                    and bool(event["bot_info"]["type"])
                )
            )
            for event in checks[0]["events"]
        )
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False


def endpoint_attribution(response: dict, result: dict, directory: Path) -> bool:
    """Accept only the declared exact admin rule with joined access/security identity."""
    if (
        response.get("scenario") != "api-protection-verify/03-protection-deny"
        or response.get("path") != "/httpbin/anything/admin"
        or response.get("method") not in {"POST", "DELETE"}
    ):
        return False
    try:
        evidence = json.loads((directory / "control-attribution.json").read_text())
        scope, bounds = evidence["scope"], evidence["clock_bounds"]
        checks = [
            check
            for check in evidence["checks"]
            if request_identity(check["response"]) == request_identity(response)
        ]
        if not (
            response.get("status") == FORBIDDEN
            and response.get("upstream_dispatched") is True
            and all(key in response for key in RESPONSE_IDENTITY_FIELDS)
            and all(
                evidence.get(key) == result.get(key)
                for key in ("source_commit", "artifact_sha256")
            )
            and len(bounds) == PAIR_LENGTH
            and -MAX_CLOCK_OFFSET <= bounds[0] <= bounds[1] <= MAX_CLOCK_OFFSET
            and len(checks) == 1
        ):
            return False
        check = checks[0]
        request_id = security_request_id(
            check,
            response,
            scope,
            bounds,
            evidence.get("event_recording_delay_seconds", 0),
        )
        if request_id is None:
            return False
        policy = "ves-io-http-loadbalancer-api-protection-" + scope["loadbalancer"]
        rule = "ves-io-service-policy-" + policy + "-api-protection-0"
        return any(
            event.get("req_id") == request_id
            and joined(
                event,
                response,
                scope,
                bounds,
                evidence.get("event_recording_delay_seconds", 0),
            )
            and event.get("action") == "block"
            and event.get("sec_event_type") == "api_sec_event"
            and event.get("sec_event_name") == "API Protection Rule"
            and any(
                hit.get("result") == "deny"
                and hit.get("policy") == policy
                and hit.get("policy_rule") == rule
                and hit.get("policy_namespace") == scope["namespace"]
                for hit in event.get("policy_hits", {}).get("policy_hits", [])
            )
            for event in check["events"]
        )
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False


def control_attribution(
    response: dict, result: dict, directory: Path, signatures: list[str]
) -> bool:
    """Validate each control through its exact configured signature or policy identity."""
    return waf_attribution(
        response, result, directory, signatures
    ) or endpoint_attribution(response, result, directory)


def attributed_responses(scenario: dict, result: dict, directory: Path) -> list[dict]:
    """Read actual response receipts and mark only fully validated WAF evidence."""
    path = directory / "response-events.jsonl"
    rows = (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )
    signatures = scenario.get("functional_contract", {}).get("waf_signatures", [])
    for row in rows:
        if control_attribution(row, result, directory, signatures):
            row["control_attributed"] = True
    return rows


# Large request sets need complete paginated XC joins before installation.
# The observed 594-request Hydra bundle took 278 seconds; keep a bounded wait.
CONTROL_WAIT_SECONDS = 900


def await_control_evidence(
    scenario: dict, result: dict, directory: Path, stop: Event
) -> None:
    """Publish actual blocked request identities for a credential-free operator handshake."""
    response_path = directory / "response-events.jsonl"
    rows = (
        [json.loads(line) for line in response_path.read_text().splitlines()]
        if response_path.is_file()
        else []
    )
    signatures = scenario.get("functional_contract", {}).get("waf_signatures", [])
    required = [
        row
        for row in rows
        if row.get("scenario") == scenario["id"]
        and row.get("kind") == "scenario"
        and row.get("status") == FORBIDDEN
        and row.get("upstream_dispatched") is True
        and row.get("outcome") != "expected_application_rejection"
    ]
    if not required:
        return
    path = directory / "control-evidence-request.json"
    atomic_json(
        path,
        {
            "schema_version": 1,
            "scenario": scenario["id"],
            "source_commit": result.get("source_commit"),
            "artifact_sha256": result.get("artifact_sha256"),
            "requests": required,
            "waf_signatures": signatures,
        },
    )
    deadline = time.monotonic() + CONTROL_WAIT_SECONDS
    while not stop.is_set():
        if all(
            control_attribution(row, result, directory, signatures) for row in required
        ):
            return
        if time.monotonic() >= deadline:
            return
        stop.wait(min(1, max(0, deadline - time.monotonic())))
