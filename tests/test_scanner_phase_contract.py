"""Spider GET requests cannot stand in for native active scanner completion."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scanner_phase_contract import verify_scanner_phases


def test_missing_unfinished_or_foreign_scans_fail():
    contract = {"phase": "active", "paths": ["/dvwa/"]}
    start = {"phase": "active", "path": "/dvwa/", "scan_id": "1", "started": True}
    end = {"phase": "active", "scan_id": "1", "completed": True, "status": 100}
    assert not verify_scanner_phases(contract, [start])["passed"]
    assert not verify_scanner_phases(contract, [start, {**end, "scan_id": "2"}])[
        "passed"
    ]
    assert not verify_scanner_phases(contract, [start, {**end, "status": 50}])["passed"]
    assert verify_scanner_phases(contract, [start, end])["passed"]


def test_completed_scan_without_native_attack_messages_fails():
    """A 100-percent phase with no attack traffic cannot establish active coverage."""
    contract = {"phase": "active", "paths": ["/dvwa/"], "minimum_messages": 1}
    start = {"phase": "active", "path": "/dvwa/", "scan_id": "1", "started": True}
    end = {"phase": "active", "scan_id": "1", "completed": True, "status": 100}
    for messages in [None, [], ["not-an-id"], ["1", "1"]]:
        assert not verify_scanner_phases(
            contract, [start, {**end, "message_ids": messages}]
        )["passed"]
    assert verify_scanner_phases(contract, [start, {**end, "message_ids": ["1", "2"]}])[
        "passed"
    ]
