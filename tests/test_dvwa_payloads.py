"""Retargeted payloads require real authenticated DVWA dispatch."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PayloadTests(unittest.TestCase):
    """Check intended dispatch and preserved scenario contracts."""

    def test_payload_counts_and_real_targets(self):
        """Require evidence from the declared payload dispatch."""
        for name, count, endpoint in [
            ("01-sqli-waf-endpoint.sh", 15, "/dvwa/vulnerabilities/sqli/"),
            ("02-xss-waf-endpoint.sh", 18, "/dvwa/vulnerabilities/xss_r/"),
        ]:
            source = (ROOT / "suites/dvwa-payloads" / name).read_text()
            payloads = source.split("PAYLOADS=(", 1)[1].split("\n)", 1)[0]
            assert (
                len([line for line in payloads.splitlines() if line.strip()]) == count
            )
            assert endpoint in source
            assert '"$COOKIES"' in source
            assert "/WAF/" not in source
            assert "dvwa-session" in source


if __name__ == "__main__":
    unittest.main()
