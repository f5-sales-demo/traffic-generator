"""Reuse declared scenario settings inside an existing shared HTTP boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Self

from traffic_family_native import host_action as family_host_action
from traffic_network import NetworkBoundary
from traffic_order_host import restore_receipt
from traffic_signup_host import host_action as signup_host_action


class InheritedBoundary(NetworkBoundary):
    """Use the parent's egress and pacing; never create another proxy or worker pool."""

    @classmethod
    def inherited(cls, root: Path) -> Self:
        """Bind only the already-declared parent inputs required by shared helpers."""
        self = cls.__new__(cls)
        self.root = root
        self.runtime = Path(os.environ["TGEN_RUNTIME_DIR"])
        self.browser_temp = Path(os.environ["TMPDIR"])
        self.config = {
            "domains": json.loads(os.environ["TGEN_AUTHORIZED_DOMAINS"]),
            "connection_rps": int(os.environ["TGEN_CONNECTION_RATE"]),
            "slow_connections": int(os.environ["TGEN_SLOW_CONNECTIONS"]),
            "source_commit": os.environ["SOURCE_COMMIT"],
            "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
        }
        return self

    def wrap(self, command: list[str], connection: bool = False) -> list[str]:
        """Descendants already inhabit the parent's HTTP network namespace."""
        if connection:
            message = "connection behavior requires the top-level catalog"
            raise ValueError(message)
        return command

    def order_fixture(self, directory: Path, action: str) -> bool:
        """The native order adapter owns prepare/restore through host jobs."""
        return action == "restore" and restore_receipt(directory)

    def recover_family(self, directory: Path, family: str) -> bool:
        """Delegate only declared family restoration to the existing owning host."""
        family_host_action(directory, "restore", family)
        return (
            json.loads((directory / "family-restoration.json").read_text()).get(
                "restored"
            )
            is True
        )

    def recover_signup(self, directory: Path) -> bool:
        """Keep forced-command recovery outside the inherited HTTP namespace."""
        signup_host_action(directory)
        return (
            json.loads((directory / "fixture-recovery-receipt.json").read_text()).get(
                "passed"
            )
            is True
        )
