"""Send preserved native order mutations and journal forced-command recovery."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid
from http import HTTPStatus
from pathlib import Path

from crapi_otp_fixture import request
from traffic_common import atomic_json

ACTOR = "tgen-order@example.com"
PAYLOADS = (
    {"status": "returned", "quantity": 100},
    {"status": "delivered", "quantity": 999, "total_price": 0},
    {"status": "return_pending", "quantity": 50},
)


def recovery(directory: Path, action: str) -> dict:
    """Use a dedicated forced SSH route with no caller-provided baseline values."""
    fixtures = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())
    settings = fixtures["order_recovery"]
    journal = json.loads((directory / "order-journal.json").read_text())
    for key in ("key", "known_hosts"):
        file = Path(settings[key])
        if file.is_symlink() or file.stat().st_mode & 0o077:
            message = "unsafe order recovery credential"
            raise ValueError(message)
    if not re.fullmatch(r"[0-9.]+", settings["host"]):
        message = "invalid owned order recovery host"
        raise ValueError(message)
    value = {
        "action": action,
        "identity": journal["identity"],
        "order": journal["order"],
    }
    result = subprocess.run(  # noqa: S603 - exact private forced-command SSH route
        [
            "/usr/bin/ssh",
            "-i",
            settings["key"],
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + settings["known_hosts"],
            "root@" + settings["host"],
            "recover-order",
        ],
        input=json.dumps(value).encode(),
        capture_output=True,
        check=True,
        timeout=60,
    )
    receipt = json.loads(result.stdout)
    atomic_json(
        directory
        / ("order-baseline.json" if action == "snapshot" else "order-restoration.json"),
        receipt,
    )
    if action == "restore" and receipt.get("restored") is not True:
        message = "order and credit restoration missing"
        raise ValueError(message)
    return receipt


def prepare(directory: Path) -> None:
    """Write unique ownership before any attack can mutate the dedicated actor."""
    fixtures = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())
    order = fixtures["crapi_dedicated_order_id"]
    if not isinstance(order, int) or isinstance(order, bool) or order <= 0:
        message = "dedicated order fixture unavailable"
        raise ValueError(message)
    journal = {
        "identity": uuid.uuid4().hex,
        "order": order,
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
    }
    atomic_json(directory / "order-journal.json", journal)
    recovery(directory, "snapshot")


def native_update(base: str, order: int, payload: dict, token: str) -> tuple[int, dict]:
    """Send the preserved mutation and retain its actual status and JSON body."""
    result = subprocess.run(  # noqa: S603 - scoped target through shared HTTP boundary
        [
            "/usr/bin/curl",
            "-sS",
            "--max-time",
            "60",
            "-X",
            "PUT",
            *(
                ["-H", "X-TGen-Child: " + os.environ["TGEN_CHILD_MARKER"]]
                if os.environ.get("TGEN_CHILD_MARKER")
                else []
            ),
            base + "/workshop/api/shop/orders/" + str(order),
            "-H",
            "Content-Type: application/json",
            "-H",
            "Authorization: Bearer " + token,
            "--data",
            json.dumps(payload),
            "-w",
            "\n%{http_code}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=65,
    )
    body, code = result.stdout.rsplit("\n", 1)
    return int(code), json.loads(body)


def run(directory: Path) -> None:
    """Exercise all three payloads through the shared HTTP boundary and native readback."""
    fixtures = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())
    journal = json.loads((directory / "order-journal.json").read_text())
    token = fixtures["crapi_order_actor_token"]
    base = "https://" + os.environ["TGEN_AUTHORIZED_HOST"] + "/crapi"
    rows = []
    for payload in PAYLOADS:
        status, response = native_update(base, journal["order"], payload, token)
        after = request(
            base, "/workshop/api/shop/orders/" + str(journal["order"]), token=token
        )
        native = response.get("orders", {})
        if status == HTTPStatus.BAD_REQUEST and payload["status"] == "return_pending":
            if not isinstance(response.get("message"), str) or not response["message"]:
                message = "native invalid status rejection missing"
                raise ValueError(message)
            native = after["order"]
        if native.get("id") != journal["order"] or after.get("order") != native:
            message = "native order mutation readback mismatch"
            raise ValueError(message)
        rows.append(
            {
                "payload": payload,
                "status": status,
                "response": native,
                "readback": after["order"],
            }
        )
    atomic_json(
        directory / "order-functional.json",
        {
            "actor": ACTOR,
            "order": journal["order"],
            "attempts": rows,
            "source_commit": journal["source_commit"],
            "artifact_sha256": journal["artifact_sha256"],
            "passed": len(rows) == len(PAYLOADS),
        },
    )


def host_action(directory: Path, action: str) -> None:
    """Request journal work from the owning host, with bounded source-bound response."""
    job = {
        "action": action,
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
        "identity": uuid.uuid4().hex,
    }
    response = directory / "order-host-response.json"
    response.unlink(missing_ok=True)
    atomic_json(directory / "order-host-request.json", job)
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        if response.exists():
            receipt = json.loads(response.read_text())
            if receipt.get("request") != job or receipt.get("passed") is not True:
                message = "host order journal action failed"
                raise ValueError(message)
            return
        time.sleep(0.5)
    message = "host order journal deadline exceeded"
    raise ValueError(message)


def main() -> None:
    """Prepare and recover outside the network namespace; attacks use paced native APIs."""
    action, destination = sys.argv[1:3]
    directory = Path(destination)
    if action == "prepare":
        prepare(directory)
    elif action == "restore":
        recovery(directory, "restore")
    elif action == "run":
        if os.environ.get("TGEN_NESTED_EXECUTION"):
            host_action(directory, "prepare")
            try:
                run(directory)
            finally:
                host_action(directory, "restore")
        else:
            run(directory)
    else:
        message = "invalid order fixture action"
        raise ValueError(message)


if __name__ == "__main__":
    main()
