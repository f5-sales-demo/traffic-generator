"""Verify declared uncached dynamic application responses and query isolation."""

import gzip
import http.client
import json
import os
import ssl
import sys
import uuid
from pathlib import Path
from urllib.parse import urlencode

import brotli
from traffic_common import atomic_json
from traffic_workload import content_identity

HTTP_OK = 200


def validate_dynamic_response(
    path: str, content_type: str, body: bytes, cache: str, query: dict
) -> bool:
    """Uncached JSON echo must preserve every query value without cross-contamination."""
    if cache not in ("NONE", "BYPASS") or not content_identity(
        path, content_type, body
    ):
        return False
    if path == "/httpbin/get":
        try:
            document = json.loads(body)
            return all(
                document.get("args", {}).get(key) == value
                for key, value in query.items()
            )
        except ValueError:
            return False
    return True


def main() -> int:
    """Retain stable suite actions with content/cache assertions and private evidence."""
    identifier, domain = sys.argv[1:3]
    if domain != os.environ["TGEN_AUTHORIZED_HOST"]:
        message = "unauthorized cache verification target"
        raise ValueError(message)
    cases: list[tuple[str, dict, dict]] = []
    if "query-string" in identifier:
        for key, path, values in [
            ("user", "/httpbin/get", ["alice", "bob", "charlie", "dave", "eve"]),
            (
                "q",
                "/juice-shop/rest/products/search",
                ["apple", "banana", "cherry", "orange", "lemon"],
            ),
            ("v", "/juice-shop/", ["1", "2", "3", "4", "5"]),
        ]:
            for value in values:
                cases.extend([(path, {key: value}, {})] * 2)
        for _ in range(20):
            cases.extend([("/httpbin/get", {"r": str(uuid.uuid4())}, {})] * 2)
        cases.extend(
            [
                ("/httpbin/get", {"iso": "alpha-" + str(os.getpid())}, {}),
                ("/httpbin/get", {"iso": "bravo-" + str(os.getpid())}, {}),
            ]
        )
    else:
        for path in ["/juice-shop/", "/httpbin/get", "/whoami/", "/health"]:
            cases.extend(
                (path, {}, {"Accept-Encoding": encoding})
                for encoding in [
                    "gzip",
                    "br",
                    "gzip, deflate",
                    "gzip, deflate, br",
                    "identity",
                    "",
                ]
            )
    checks = []
    connection = http.client.HTTPSConnection(
        domain, context=ssl.create_default_context(), timeout=15
    )
    try:
        for path, query, headers in cases:
            check = {
                "path": path,
                "query": query,
                "encoding": headers.get("Accept-Encoding"),
                "passed": False,
            }
            try:
                connection.request(
                    "GET",
                    path + ("?" + urlencode(query) if query else ""),
                    headers=headers,
                )
                response = connection.getresponse()
                body = response.read()
                content_type = response.getheader("Content-Type", "")
                encoding = response.getheader("Content-Encoding", "")
                if encoding == "gzip":
                    body = gzip.decompress(body)
                elif encoding == "br":
                    body = brotli.decompress(body)
                cache = response.getheader("X-Cache-Status", "NONE")
                check.update(status=response.status, cache=cache)
                check["passed"] = response.status == HTTP_OK and (
                    validate_dynamic_response(path, content_type, body, cache, query)
                    if path != "/health"
                    else cache in ("NONE", "BYPASS") and b"origin-server" in body
                )
            except (OSError, ValueError, http.client.HTTPException):
                check["error"] = "content or transport verification failed"
                connection.close()
            checks.append(check)
    finally:
        connection.close()
    atomic_json(
        Path(os.environ["TGEN_RESULTS_DIR"]) / "cache-evidence.json",
        {
            "scenario": identifier,
            "cache_mode": "dynamic-bypass",
            "checks": checks,
            "passed": bool(checks) and all(check["passed"] for check in checks),
        },
    )
    return int(any(not check["passed"] for check in checks))


if __name__ == "__main__":
    raise SystemExit(main())
