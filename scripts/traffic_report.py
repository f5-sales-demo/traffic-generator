"""Aggregate verified current-pass receipts without inferring exploit or control success."""

import hashlib
import json
import os
import sys
from pathlib import Path

SHA256_LENGTH = 64


def build_report(
    pass_directory: Path, dependencies: list[str], source_digests: dict | None = None
) -> dict:
    """Require every dependency's source digest, observed action and successful execution."""
    checks = []
    for identifier in dependencies:
        path = pass_directory / identifier.replace("/", "--") / "receipt.json"
        result = {"id": identifier, "passed": False}
        try:
            payload = path.read_bytes()
            receipt = json.loads(payload)
            result.update(
                receipt_sha256=hashlib.sha256(payload).hexdigest(),
                source_sha256=receipt.get("source_sha256"),
                outcome=receipt.get("outcome"),
            )
            result["passed"] = (
                receipt.get("id") == identifier
                and receipt.get("outcome") == "launched"
                and receipt.get("dispatch_contract_verified") is True
                and len(receipt.get("source_sha256", "")) == SHA256_LENGTH
                and (
                    source_digests is None
                    or receipt.get("source_sha256") == source_digests.get(identifier)
                )
            )
        except (OSError, ValueError, TypeError):
            result["error"] = "dependency receipt missing or invalid"
        checks.append(result)
    return {
        "schema_version": 1,
        "passed": bool(checks) and all(check["passed"] for check in checks),
        "claim": "observed scenario execution only",
        "dependencies": checks,
    }


def main() -> int:
    """Write private report provenance next to its scenario receipt."""
    root = Path(__file__).resolve().parents[1]
    catalog = json.loads((root / "suites/catalog.json").read_text())
    scenario = next(item for item in catalog["scenarios"] if item["id"] == sys.argv[1])
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    dependencies = scenario["report_contract"]["dependencies"]
    digests = {
        item["id"]: hashlib.sha256((root / item["entrypoint"]).read_bytes()).hexdigest()
        for item in catalog["scenarios"]
        if item["id"] in dependencies
    }
    report = build_report(directory.parent, dependencies, digests)
    path = directory / "report-evidence.json"
    path.write_text(json.dumps(report))
    path.chmod(0o600)
    print(json.dumps(report))
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
