"""Validate supplied private control evidence against each actual native request."""

import json
from datetime import datetime
from pathlib import Path

FORBIDDEN = 403
PAIR_LENGTH = 2
MAX_CLOCK_OFFSET = 5
SHA256_LENGTH = 64
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


def joined(record: dict, response: dict, scope: dict, bounds: list) -> bool:
    """Require scope, request identity, response status and calibrated time."""
    try:
        moment = datetime.fromisoformat(record["time"]).timestamp()
        return (
            response["sent_at"] + bounds[0]
            <= moment
            <= response["received_at"] + bounds[1]
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
        access = checks[0]["access"]
        if not access.get("req_id") or not joined(access, response, scope, bounds):
            return False
        return any(
            event.get("req_id") == access["req_id"]
            and joined(event, response, scope, bounds)
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
