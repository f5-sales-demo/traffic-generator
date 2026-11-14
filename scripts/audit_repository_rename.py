#!/usr/bin/env python3
"""Audit maintained repository identities, preserving exactly classified evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

OLD_NAME = "c" + "sd"
OLD_IDENTITY = "f5-sales-demo/" + OLD_NAME
IDENTITY = re.compile(
    rf"f5-sales-demo(?:/|:|\.github\.io/){OLD_NAME}(?=$|[^a-zA-Z0-9_-])"
    rf"|arc-runners-{OLD_NAME}(?=$|-)"
    rf"|\b{OLD_NAME}-(?:socketless|container-build)\b"
    rf"|arc/repositories/{OLD_NAME}\.yaml"
    rf"|\b{OLD_NAME}#[0-9]+"
    rf"|(?<![a-zA-Z0-9:/.-])/{OLD_NAME}/|\./{OLD_NAME}/"
    rf"|\bcd[ \t]+{OLD_NAME}(?=$|[\s;/])"
)
REPOSITORY_TOKEN = re.compile(
    rf"[\"']{OLD_NAME}[\"']|^\s*-\s+{OLD_NAME}\s*$",
    re.MULTILINE,
)
CATALOG_PATHS = {
    ".claude/governance.json",
    ".github/actionlint.yaml",
    ".github/config/downstream-repos.json",
    ".github/config/repo-settings.json",
    "scripts/audit-runner-workflows.py",
    "scripts/ephemeral-runner-controller.py",
    "scripts/workflow_security_validator.py",
    "scripts/arc-config.py",
    "ecosystem/search.mjs",
}


def findings(path: str, content: bytes) -> list[dict]:
    """Product CSD names and Shape API endpoints are outside identity patterns."""
    if b"\0" in content:
        return []
    text = content.decode("utf-8", errors="replace")
    patterns = [IDENTITY]
    if path in CATALOG_PATHS:
        patterns.append(REPOSITORY_TOKEN)
    matches = {hit.start() for pattern in patterns for hit in pattern.finditer(text)}
    offsets = sorted(matches)
    return [
        {
            "path": path,
            "line": text.count("\n", 0, offset) + 1,
        }
        for offset in offsets
    ]


def audit(root: Path, repository: str, classifications: dict) -> dict:
    """Compare all maintained sources with exact historical evidence records."""
    names = (
        subprocess.run(
            [
                "/usr/bin/git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            cwd=root,
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .split("\0")
    )
    records = classifications.get("repositories", {}).get(repository, {})
    rejected, accepted, errors = [], [], []
    observed = set()
    for name in filter(None, names):
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        content = path.read_bytes()
        matches = findings(name, content)
        record = records.get(name)
        if record is not None:
            observed.add(name)
            valid = (
                record.get("category") in {"historical", "audit-assertion"}
                and bool(record.get("reason"))
                and record.get("sha256") == hashlib.sha256(content).hexdigest()
                and record.get("matches") == len(matches)
                and len(matches) > 0
            )
            if not valid:
                errors.append(
                    {
                        "path": name,
                        "error": "classification does not match exact evidence bytes/count",
                    }
                )
                continue
            accepted.append(
                {
                    "path": name,
                    "category": record["category"],
                    "matches": len(matches),
                },
            )
        else:
            rejected.extend(matches)
    errors.extend(
        {
            "path": name,
            "error": "classified evidence is missing from tracked source inventory",
        }
        for name in records.keys() - observed
    )
    return {
        "repository": repository,
        "files_scanned": len(list(filter(None, names))),
        "stale_operational_references": rejected,
        "classified_evidence": accepted,
        "errors": errors,
    }


def main() -> int:
    """Run the identity audit and return failure for stale or invalid evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--repository", required=True)
    parser.add_argument("--classifications", type=Path)
    args = parser.parse_args()
    classifications = {"schema_version": 1, "repositories": {}}
    if args.classifications:
        classifications = json.loads(args.classifications.read_text())
        if classifications.get("schema_version") != 1:
            parser.error("unsupported classification schema")
    result = audit(args.root, args.repository, classifications)
    print(json.dumps(result, indent=2))
    return int(bool(result["stale_operational_references"] or result["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
