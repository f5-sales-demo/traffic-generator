"""Setup, filler and wrong endpoints cannot establish intended scenario dispatch."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class DispatchTests(unittest.TestCase):
    def test_only_matching_method_path_and_payload_count(self):
        from traffic_dispatch import verify_dispatch  # noqa: PLC0415, I001 - CLI import in isolated test

        contract = {
            "method": "GET",
            "path": "/dvwa/vulnerabilities/sqli/",
            "parameter": "id",
            "payload_class": "sqli",
            "minimum_dispatches": 2,
        }
        setup = {
            "method": "POST",
            "path": "/dvwa/login.php",
            "query": "",
            "kind": "scenario",
        }
        attack = {
            "method": "GET",
            "path": "/dvwa/vulnerabilities/sqli/",
            "query": "id=%27+OR+1%3D1--&Submit=Submit",
            "kind": "scenario",
        }
        assert not verify_dispatch(contract, [setup])["passed"]
        assert not verify_dispatch(contract, [attack, dict(attack, kind="filler")])[
            "passed"
        ]
        assert not verify_dispatch(contract, [dict(attack, method="POST"), attack])[
            "passed"
        ]
        assert verify_dispatch(contract, [attack, attack])["passed"]


if __name__ == "__main__":
    unittest.main()
