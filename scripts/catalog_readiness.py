#!/usr/bin/env python3
"""Strict installed catalog, browser, TLS, and application route readiness."""

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from traffic_catalog import load_catalog, readiness
from traffic_runtime import validate_config

HTTP_ERROR_START, METHOD_NOT_ALLOWED = 400, 405


def main() -> int:
    """Missing prerequisites or invalid upstream certificates fail start."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    validate_config(config)
    root = Path(__file__).resolve().parents[1]
    catalog = load_catalog(root)
    result = readiness(root, catalog)
    result["missing_assets"] = [
        p for p in catalog["required_assets"] if not Path(p).is_file()
    ]
    node = shutil.which("node") or "/usr/bin/node"
    browser = subprocess.run(  # noqa: S603 - fixed browser runtime readiness
        [
            node,
            "-e",
            "const p=require('playwright'); const fs=require('fs'); fs.accessSync(p.chromium.executablePath(),fs.constants.X_OK)",
        ],
        capture_output=True,
        check=False,
    )
    result["browser_ready"] = browser.returncode == 0
    checks = []
    paths = sorted(
        {path for scenario in catalog["scenarios"] for path in scenario["target_paths"]}
    )
    for domain in config["domains"]:
        for protocol in ("http", "https"):
            for path in paths:
                try:
                    request = Request(protocol + "://" + domain + path)  # noqa: S310 - validated HTTP(S) targets
                    if path.endswith("/graphql"):
                        request = Request(  # noqa: S310 - validated HTTP(S) target
                            protocol + "://" + domain + path,
                            data=b'{"query":"{ __typename }"}',
                            headers={"Content-Type": "application/json"},
                        )
                    with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed HTTP(S) schemes
                        code = response.status
                    checks.append(
                        {
                            "domain": domain,
                            "protocol": protocol,
                            "path": path,
                            "ready": code < HTTP_ERROR_START,
                        }
                    )
                except HTTPError as error:
                    checks.append(
                        {
                            "domain": domain,
                            "protocol": protocol,
                            "path": path,
                            "ready": error.code == METHOD_NOT_ALLOWED,
                        }
                    )
                except OSError:
                    checks.append(
                        {
                            "domain": domain,
                            "protocol": protocol,
                            "path": path,
                            "ready": False,
                        }
                    )
    result["routes"] = checks
    result["ready"] = (
        result["ready"]
        and not result["missing_assets"]
        and result["browser_ready"]
        and all(c["ready"] for c in checks)
    )
    print(json.dumps(result))
    return int(not result["ready"])


if __name__ == "__main__":
    raise SystemExit(main())
