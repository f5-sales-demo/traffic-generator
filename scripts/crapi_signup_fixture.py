#!/usr/bin/env python3
"""Run one real journaled signup and reset workflow with forced-command recovery."""

import base64
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

from crapi_mail import decode_message, extract, owned_messages
from crapi_otp_fixture import request
from traffic_common import atomic_json

JWT_PARTS = 3


class Signup:
    """Bound one synthetic identity to native signup, vehicle and reset responses."""

    def __init__(self, base: str, directory: Path) -> None:
        """Journal before sending the first request."""
        self.base, self.directory = base, directory
        suffix = uuid.uuid4().hex
        self.journal: dict = {
            "email": "signup-" + suffix + "@example.com",
            "number": "555" + str(int(suffix[:6], 16)).zfill(7)[-7:],
            "vehicle_vin": None,
            "mail_ids": [],
        }
        self.persist()

    def persist(self) -> None:
        """Retain exact ownership for interrupted cleanup."""
        atomic_json(self.directory / "fixture-journal.json", self.journal)

    def mail(self, kind: str) -> tuple[dict, dict]:
        """Poll only owned native MIME mail within a fixed bound."""
        for _ in range(15):
            document = request(self.base, "/mailhog/api/v2/messages?limit=1000")
            self.journal["mail_ids"] = [
                m["ID"] for m in owned_messages(document, self.journal["email"])
            ]
            self.persist()
            try:
                return document, extract(document, self.journal["email"], kind)
            except ValueError:
                time.sleep(1)
        message = "native signup mail unavailable"
        raise ValueError(message)

    def login(self, password: str) -> str:
        """Require an origin-issued JWT whose subject is this journaled actor."""
        response = request(
            self.base,
            "/identity/api/auth/login",
            {"email": self.journal["email"], "password": password},
            method="POST",
        )
        token = response.get("token", "")
        parts = token.split(".")
        if len(parts) != JWT_PARTS:
            message = "native signup token missing"
            raise ValueError(message)
        claims = json.loads(
            base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        )
        if claims.get("sub") != self.journal["email"]:
            message = "native signup token actor mismatch"
            raise ValueError(message)
        return token

    def execute(self) -> dict:
        """Verify welcome vehicle and real reset OTP without substituting seeded actors."""
        password = "Synthetic!123"  # noqa: S105 - synthetic disposable lab credential
        request(
            self.base,
            "/identity/api/auth/signup",
            {
                **{k: self.journal[k] for k in ("email", "number")},
                "name": "Synthetic catalog actor",
                "password": password,
            },
            method="POST",
        )
        self.journal["submitted"] = True
        self.persist()
        document, welcome = self.mail("welcome")
        self.journal["vehicle_vin"] = welcome["value"]
        self.persist()
        native = next(m for m in document["items"] if m["ID"] == welcome["message_id"])
        pincode = re.search(r"Pincode:[\s\S]*?>([0-9]{4,8})<", decode_message(native))
        if not pincode:
            message = "native welcome pincode missing"
            raise ValueError(message)
        token = self.login(password)
        request(
            self.base,
            "/identity/api/v2/vehicle/add_vehicle",
            {"vin": welcome["value"], "pincode": pincode[1]},
            token,
            "POST",
        )
        self.journal["vehicle_registered"] = True
        self.persist()
        vehicles = request(self.base, "/identity/api/v2/vehicle/vehicles", token=token)
        if (
            not isinstance(vehicles, list)
            or len(vehicles) != 1
            or vehicles[0].get("vin") != welcome["value"]
        ):
            message = "native signup vehicle ownership mismatch"
            raise ValueError(message)
        request(
            self.base,
            "/identity/api/auth/forget-password",
            {"email": self.journal["email"]},
            method="POST",
        )
        _, otp = self.mail("otp")
        response = request(
            self.base,
            "/identity/api/auth/v2/check-otp",
            {
                "email": self.journal["email"],
                "otp": otp["value"],
                "password": "SyntheticReset!123",
            },
            method="POST",
        )
        if response.get("message") != "OTP verified":
            message = "native reset postcondition missing"
            raise ValueError(message)
        self.login("SyntheticReset!123")
        return {
            "passed": True,
            "signup": True,
            "welcome_vehicle": True,
            "actor_login": True,
            "reset_otp": True,
            "reset_login": True,
        }


def recover(directory: Path) -> dict:
    """Only a private enrolled forced-command route may remove the journaled actor."""
    settings = json.loads(Path(os.environ["TGEN_FIXTURES"]).read_text())[
        "signup_recovery"
    ]
    for key in ("key", "known_hosts"):
        path = Path(settings[key])
        if path.is_symlink() or path.stat().st_mode & 0o077:
            message = "unsafe signup recovery credential"
            raise ValueError(message)
    if not re.fullmatch(r"[0-9.]+", settings["host"]):
        message = "invalid owned signup recovery host"
        raise ValueError(message)
    completed = subprocess.run(  # noqa: S603 - private enrolled forced-command SSH route
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
            "recover-signup",
        ],
        input=(directory / "fixture-journal.json").read_bytes(),
        capture_output=True,
        check=True,
        timeout=60,
    )
    receipt = json.loads(completed.stdout)
    atomic_json(directory / "fixture-recovery-receipt.json", receipt)
    if not receipt.get("passed"):
        message = "exact signup recovery failed"
        raise ValueError(message)
    return receipt


def main() -> int:
    """Recover in finally; failures cannot qualify signup acceptance."""
    base = "https://" + os.environ["TGEN_AUTHORIZED_HOST"] + "/crapi"
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    actor = Signup(base, directory)
    evidence = {
        "passed": False,
        "source_commit": os.environ["SOURCE_COMMIT"],
        "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
    }
    try:
        evidence.update(actor.execute())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        evidence["passed"] = False
    finally:
        evidence["recovery"] = recover(directory)
        atomic_json(directory / "signup-functional.json", evidence)
    return int(not evidence["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
