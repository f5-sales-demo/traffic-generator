#!/usr/bin/env python3
"""Recover only a recorded task-owned traffic namespace after supervisor termination."""

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path


def cleanup(runtime: Path) -> None:
    """Delete exact recorded task-owned rules and namespace; never flush shared rules."""
    receipt = runtime / "network-owner.json"
    if not receipt.exists():
        return
    if receipt.is_symlink():
        message = "unsafe network owner receipt"
        raise ValueError(message)
    data = json.loads(receipt.read_text())
    namespace, link, chain = data["namespace"], data["host_link"], data["chain"]
    if (
        not re.fullmatch(r"tgen-[0-9a-f]{7}", namespace)
        or link != "tgh" + namespace[5:]
        or chain != "TGEN" + namespace[5:].upper()
    ):
        message = "invalid task-owned namespace identity"
        raise ValueError(message)
    commands = [
        ["iptables", "-D", "INPUT", "-i", link, "-j", "DROP"],
        [
            "iptables",
            "-D",
            "INPUT",
            "-i",
            link,
            "-p",
            "tcp",
            "--dport",
            "18080",
            "-j",
            "ACCEPT",
        ],
        ["iptables", "-D", "FORWARD", "-i", link, "-j", "DROP"],
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", link, "-j", chain],
        ["iptables", "-t", "nat", "-F", chain],
        ["iptables", "-t", "nat", "-X", chain],
        ["ip", "link", "delete", link],
        ["ip", "netns", "delete", namespace],
    ]
    for command in commands:
        subprocess.run(  # noqa: S603 - validated task-owned cleanup argv
            command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    temp = Path(data.get("browser_temp", ""))
    if (
        temp.parent == Path("/tmp")  # noqa: S108 - validated recorded private temporary directory
        and re.fullmatch(r"tgen-[a-zA-Z0-9_-]+", temp.name)
        and temp.exists()
        and not temp.is_symlink()
    ):
        shutil.rmtree(temp)
    netns = Path("/etc/netns") / namespace
    if netns.exists() and not netns.is_symlink():
        shutil.rmtree(netns)
    receipt.unlink()


def main() -> None:
    """Read the configured private runtime owner ledger."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    runtime = Path(json.loads(args.config.read_text())["results_dir"])
    cleanup(runtime)


if __name__ == "__main__":
    main()
