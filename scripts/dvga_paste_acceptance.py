"""Require each actual paste outcome and exact native recovery."""

import json
from pathlib import Path

from dvga_paste_fixture import CONTENT, HTTP_OK, PAYLOADS
from traffic_security import waf_attribution

FORBIDDEN = 403


def verify_pastes(scenario: dict, result: dict, directory: Path) -> dict:
    """Missing, stale, malformed or incomplete paste evidence cannot qualify."""
    try:
        journal = json.loads((directory / "paste-journal.json").read_text())
        recovery = json.loads((directory / "paste-restoration.json").read_text())
        attempts = journal["attempts"]
        objects = journal["objects"]
        indices = set(range(len(PAYLOADS)))
        path = directory / "response-events.jsonl"
        responses = (
            [json.loads(line) for line in path.read_text().splitlines()]
            if path.exists()
            else []
        )

        def observed(attempt: dict) -> bool:
            index = attempt["index"]
            matches = [
                r
                for r in responses
                if "xss-" + str(index) in r.get("matched_requirements", [])
                and r.get("kind") == "scenario"
            ]
            if (
                len(matches) != 1
                or not matches[0].get("upstream_dispatched")
                or matches[0].get("transport_error")
                or matches[0].get("status") != attempt.get("status")
            ):
                return False
            if attempt.get("status") == FORBIDDEN:
                return waf_attribution(
                    matches[0],
                    result,
                    directory,
                    scenario["functional_contract"].get("waf_signatures", []),
                )
            return (
                attempt.get("stored") is True
                and attempt.get("status") == HTTP_OK
                and attempt["readback"]["title"] == objects[index]["title"]
                and str(attempt["readback"]["id"]) == str(objects[index]["id"])
                and attempt["readback"]["content"] == CONTENT + "|" + PAYLOADS[index]
            )

        passed = (
            len(attempts) == len(objects) == len(recovery["objects"]) == len(PAYLOADS)
            and {a["index"] for a in attempts}
            == {o["index"] for o in objects}
            == {o["index"] for o in recovery["objects"]}
            == indices
            and recovery["identity"] == journal["identity"]
            and all(
                journal.get(k) == recovery.get(k) == result.get(k) and result.get(k)
                for k in ("source_commit", "artifact_sha256")
            )
            and all(observed(a) for a in attempts)
            and all(
                o.get("removed") is True
                and "after" in o
                and o["after"] is None
                and o["title"] == objects[o["index"]]["title"]
                for o in recovery["objects"]
            )
            and recovery.get("restored") is True
            and result.get("paste_restoration") is True
            and result.get("outcome") == "launched"
            and result.get("dispatch_contract_verified") is True
            and result.get("transport_failures") == 0
            and result.get("tool_cancellations") == 0
        )
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        passed = False
    return {
        "passed": bool(passed),
        "behavior": scenario["functional_contract"]["behavior"],
        "claim": "native stored content and owned removal; browser execution and control attribution separate",
    }
