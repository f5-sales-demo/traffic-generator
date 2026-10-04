"""Journal isolated OTP mail and restore its synthetic actor through native curl APIs."""

import json
import os
import subprocess
import sys
from pathlib import Path

from crapi_mail import owned_messages
from traffic_common import atomic_json


def request(
    base: str,
    path: str,
    payload: dict | None = None,
    token: str = "",
    method: str = "GET",
) -> dict:
    """Invoke actual curl inside the inherited shared pacing boundary."""
    arguments = [
        "/usr/bin/curl",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "60",
        "-X",
        method,
        "-H",
        "X-MUD-User: waap-fixture-benign",
    ]
    if payload is not None:
        arguments.extend(
            ["-H", "Content-Type: application/json", "--data", json.dumps(payload)]
        )
    if token:
        arguments.extend(["-H", "Authorization: Bearer " + token])
    process = subprocess.run([*arguments, base + path], capture_output=True, check=True)  # noqa: S603 - fixed native curl and validated owned base
    return json.loads(process.stdout) if process.stdout.strip() else {}


def verify_restoration(directory: Path, scenario: dict, result: dict) -> None:
    """Catalog dispatch cannot qualify an OTP mutation with absent recovery."""
    if not scenario.get("fixture_contract", {}).get("restore_otp"):
        return
    evidence = directory / "otp-restoration.json"
    restored = (
        evidence.exists() and json.loads(evidence.read_text()).get("restored") is True
    )
    result["otp_restoration"] = restored
    result["dispatch_contract_verified"] &= restored
    if not restored:
        result["outcome"] = "fixture_failure"


def main() -> int:
    """Require baseline auth; recovery uses the same actor and removes only new owned mail."""
    action, base = sys.argv[1:3]
    if base != "https://" + os.environ["TGEN_AUTHORIZED_HOST"] + "/crapi":
        message = "OTP fixture target mismatch"
        raise ValueError(message)
    fixtures = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())
    email, password = fixtures["crapi_otp_email"], fixtures["crapi_otp_password"]
    if email != "tgen-otp@example.com":
        message = "OTP mutation actor must be isolated"
        raise ValueError(message)
    output = Path(os.environ["TGEN_RESULTS_DIR"])
    journal = output / "otp-fixture-journal.json"
    token = fixtures["crapi_otp_actor_token"]
    if action == "snapshot":
        login = request(
            base,
            "/identity/api/auth/login",
            {"email": email, "password": password},
            method="POST",
        )
        if not login.get("token"):
            message = "isolated OTP baseline authentication failed"
            raise ValueError(message)
        messages = request(base, "/mailhog/api/v2/messages?limit=1000")
        atomic_json(
            journal,
            {
                "email": email,
                "token": login["token"],
                "mail_ids": [m["ID"] for m in owned_messages(messages, email)],
            },
        )
        print(json.dumps({"email": email, "password": password}))
    elif action == "restore":
        before = json.loads(journal.read_text())
        if before["email"] != email:
            message = "OTP recovery journal actor changed"
            raise ValueError(message)
        token = before["token"]
        request(
            base,
            "/identity/api/v2/user/reset-password",
            {"email": email, "password": password},
            token,
            "POST",
        )
        login = request(
            base,
            "/identity/api/auth/login",
            {"email": email, "password": password},
            method="POST",
        )
        if not login.get("token"):
            message = "native OTP password restoration failed"
            raise ValueError(message)
        messages = request(base, "/mailhog/api/v2/messages?limit=1000")
        removed = []
        for item in owned_messages(messages, email):
            if item["ID"] not in before["mail_ids"]:
                request(base, "/mailhog/api/v1/messages/" + item["ID"], method="DELETE")
                removed.append(item["ID"])
        after = request(base, "/mailhog/api/v2/messages?limit=1000")
        remaining = {m["ID"] for m in owned_messages(after, email)}
        atomic_json(
            output / "otp-restoration.json",
            {
                "restored": not (set(removed) & remaining),
                "email": email,
                "native_login": True,
                "new_mail_removed": len(removed),
            },
        )
    else:
        message = "unknown OTP fixture action"
        raise ValueError(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
