"""The native JWT transformations must decode all URL-safe payload bytes."""

import base64
import re
import subprocess
from pathlib import Path


def test_native_jwt_decode_preserves_complete_header_and_payload():
    source = (
        Path(__file__).parents[1] / "suites/juice-shop-exploits/10-jwt-attacks.sh"
    ).read_text()
    match = re.search(r"b64url_decode\(\) \{.*?^\}", source, re.MULTILINE | re.DOTALL)
    assert match is not None
    for original in (
        b'{"alg":"RS256","typ":"JWT"}',
        b'{"data":{"id":17,"email":"synthetic@example.com","role":"customer"}}',
        bytes(range(256)),
    ):
        encoded = base64.urlsafe_b64encode(original).decode().rstrip("=")
        result = subprocess.run(  # noqa: S603 - checked-in native decoder and synthetic opaque bytes
            [
                "/bin/bash",
                "-o",
                "pipefail",
                "-c",
                match.group() + '\nb64url_decode "$1"',
                "jwt-regression",
                encoded,
            ],
            capture_output=True,
            check=False,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == original


def test_original_gnu_decoder_rejects_the_unescaped_option():
    result = subprocess.run(  # noqa: S603 - fixed native regression against synthetic bytes
        ["/usr/bin/tr", "-_", "+/"],
        input=b"synthetic",
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert result.returncode != 0
    assert b"invalid option" in result.stderr
