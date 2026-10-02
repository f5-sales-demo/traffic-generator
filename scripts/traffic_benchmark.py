#!/usr/bin/env python3
"""Bounded keepalive and multi-client equivalents for standalone hardware benches."""

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    """Preserve multiple paths and connection behavior without host tuning."""
    scenario, domain = sys.argv[1:3]
    if domain != os.environ["TGEN_AUTHORIZED_HOST"]:
        msg = "unauthorized benchmark target"
        raise ValueError(msg)
    paths = ["/httpbin/get", "/juice-shop/", "/dvwa/", "/vampi/"]

    def request(index: int) -> int:
        """Issue one request inside the enforced scenario namespace."""
        try:
            headers = {
                "Connection": "keep-alive" if "keepalive" in scenario else "close"
            }
            with urlopen(
                Request(
                    "https://" + domain + paths[index % len(paths)], headers=headers
                ),
                timeout=10,
            ) as response:
                response.read()
                return response.status
        except HTTPError as error:
            return error.code
        except (OSError, URLError):
            return 0

    with ThreadPoolExecutor(
        max_workers=min(20, int(os.environ["TGEN_CONCURRENCY"]))
    ) as pool:
        codes = list(pool.map(request, range(int(os.environ["TGEN_REQUESTS"]))))
    receipt = {
        "scenario": scenario,
        "execution": "bounded benchmark equivalent",
        "requests": len(codes),
        "outcomes": {str(code): codes.count(code) for code in set(codes)},
        "host_tuning": False,
    }
    path = Path(os.environ["TGEN_RESULTS_DIR"]) / "benchmark.json"
    path.write_text(json.dumps(receipt))
    path.chmod(0o600)
    print(json.dumps(receipt))
    return int(0 in codes)


if __name__ == "__main__":
    raise SystemExit(main())
