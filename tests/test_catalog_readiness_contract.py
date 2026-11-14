"""Readiness checks application content without treating intentional negatives as outages."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from catalog_readiness import application_readiness_paths, content_matches  # noqa: E402


def test_application_readiness_excludes_attack_and_shadow_endpoints():
    """A missing intentional attack path must not block healthy applications."""
    paths = application_readiness_paths(ROOT)
    assert "/httpbin/get" in paths
    assert "/vampi/openapi.json" in paths
    assert "/api/internal/healthz-secret" not in paths
    assert "/vampi/books/v1/not-an-integer" not in paths


def test_wrong_content_200_fails_application_readiness():
    """Expected identity and content type are both required."""
    page = {"content_type": "application/json", "identity": "VAmPI"}
    assert not content_matches(page, "text/html", "VAmPI")
    assert not content_matches(page, "application/json", "Origin Server")
    assert content_matches(page, "application/json", '{"message":"VAmPI"}')
