"""Interrupted proxy ownership must be checked before signalling a process."""

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cleanup_network import stop_owned_proxy  # noqa: E402


def test_proxy_pid_reuse_never_signals_unrelated_process():
    """A PID alone is insufficient ownership evidence."""
    receipt = {
        "proxy_pid": 12345,
        "proxy_start_ticks": "100",
        "proxy_script": "/opt/traffic-generator/source-a/scripts/traffic_proxy.py",
    }
    with (
        patch(
            "cleanup_network.Path.read_text",
            return_value="12345 (worker) S " + "0 " * 18 + "200",
        ),
        patch("cleanup_network.os.kill") as kill,
    ):
        stop_owned_proxy(receipt)
    kill.assert_not_called()


def test_proxy_command_mismatch_never_signals_process():
    """The recorded script and start time must both match the live process."""
    receipt = {
        "proxy_pid": 12345,
        "proxy_start_ticks": "100",
        "proxy_script": "/opt/traffic-generator/source-a/scripts/traffic_proxy.py",
    }
    with (
        patch(
            "cleanup_network.Path.read_text",
            return_value="12345 (worker) S " + "0 " * 18 + "100",
        ),
        patch("cleanup_network.Path.read_bytes", return_value=b"other-worker\0"),
        patch("cleanup_network.os.kill") as kill,
    ):
        stop_owned_proxy(receipt)
    kill.assert_not_called()


def test_same_owned_proxy_is_signalled():
    """Start time and command identity together establish process ownership."""
    receipt = {
        "proxy_pid": 12345,
        "proxy_start_ticks": "100",
        "proxy_script": "/opt/traffic-generator/source-a/scripts/traffic_proxy.py",
    }
    command = b"/opt/traffic-generator/venv/bin/python\0/opt/traffic-generator/venv/bin/mitmdump\0-s\0/opt/traffic-generator/source-a/scripts/traffic_proxy.py\0"
    with (
        patch(
            "cleanup_network.Path.read_text",
            return_value="12345 (worker) S " + "0 " * 18 + "100",
        ),
        patch("cleanup_network.Path.read_bytes", return_value=command),
        patch("cleanup_network.os.kill") as kill,
    ):
        stop_owned_proxy(receipt)
    assert kill.call_count == 1
