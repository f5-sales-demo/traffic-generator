"""Traffic safety and recovery failure contracts."""

import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import traffic_runtime as runtime  # noqa: E402 - scripts under test


class RuntimeTests(unittest.TestCase):
    def config(self):
        return {
            "schema_version": 1,
            "domains": ["www.example.test", "api.example.test"],
            "protocol": "https",
            "http_rps": 200,
            "benign_rps": 180,
            "attack_rps": 20,
            "connection_rps": 20,
            "slow_connections": 20,
            "csd_enabled": False,
            "protections_enabled": True,
            "scenario_timeout_seconds": 900,
            "retention_days": 7,
            "retention_bytes": 10 * 1024**3,
            "results_dir": "/opt/traffic-generator/runtime",
            "source_commit": "a" * 40,
            "artifact_sha256": "b" * 64,
        }

    def test_configuration_rejects_relaxed_bounds(self):
        for key, value in [
            ("attack_rps", 21),
            ("connection_rps", 21),
            ("slow_connections", 21),
            ("csd_enabled", True),
            ("protections_enabled", False),
            ("scenario_timeout_seconds", 901),
            ("protocol", "http"),
            ("domains", ["www.example.test"]),
            ("http_rps", 400),
        ]:
            config = self.config()
            config[key] = value
            with (
                self.subTest(key=key),
                pytest.raises(ValueError, match=r"budget|bound|domains|HTTPS|domain"),
            ):
                runtime.validate_config(config)

    def test_unknown_configuration_keys_fail_before_runtime(self):
        config = self.config()
        config["disable_waf"] = True
        with pytest.raises(ValueError, match="unknown"):
            runtime.validate_config(config)

    def test_shared_pacing_under_parallel_workers(self):
        pacer = __import__("traffic_common").Pacer(20)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=8) as pool:
            times = list(pool.map(lambda _: pacer.acquire(), range(21)))
        assert max(times) - started >= 0.99
        assert (
            min(b - a for a, b in zip(sorted(times), sorted(times)[1:], strict=False))
            >= 0.045
        )

    def test_timeout_kills_background_descendant(self):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = pathlib.Path(tmp) / "pid"
            command = [
                "bash",
                "-c",
                'sleep 1000 & echo $! > "$1"; wait',
                "bash",
                str(pid_file),
            ]
            result = runtime.execute(
                command, pathlib.Path(tmp) / "log", os.environ.copy(), 0.3
            )
            assert result["outcome"] == "timeout"
            pid = int(pid_file.read_text())
            for _ in range(30):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                stat = pathlib.Path(f"/proc/{pid}/stat")
                assert stat.exists()
                assert stat.read_text().split()[2] == "Z"

    def test_outer_deadline_kills_nested_workers_in_inherited_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            pid_file = root / "pid"
            code = "import os,pathlib; from traffic_runtime import execute; env=dict(os.environ,TGEN_NESTED_EXECUTION='1'); execute(['bash','-c','sleep 1000 & echo $! > \"$1\"; wait','bash',os.environ['PID_FILE']],pathlib.Path(os.environ['CHILD_LOG']),env,1000)"
            environment = dict(
                os.environ,
                PYTHONPATH=str(ROOT / "scripts"),
                PID_FILE=str(pid_file),
                CHILD_LOG=str(root / "nested.log"),
            )
            result = runtime.execute(
                [sys.executable, "-c", code], root / "outer.log", environment, 0.5
            )
            assert result["outcome"] == "timeout"
            pid = int(pid_file.read_text())
            for _ in range(30):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                stat = pathlib.Path(f"/proc/{pid}/stat")
                assert stat.exists()
                assert stat.read_text().split()[2] == "Z"

    def test_removed_evidence_log_is_recorded_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            log = root / "scenario" / "scenario.log"
            result = runtime.execute(
                ["/bin/bash", "-c", 'rm -rf "$1"', "bash", str(log.parent)],
                log,
                os.environ.copy(),
                5,
            )
            assert result["outcome"] == "tool_failure"
            assert log.exists()

    def test_nonzero_and_skips_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            for body, outcome in [
                ("echo SKIP: fixture unavailable", "fixture_failure"),
                ("echo '    [SKIP] scanner missing'", "fixture_failure"),
                (
                    "echo '    [FAIL] No video ID available for command injection test'",
                    "fixture_failure",
                ),
                ("exit 2", "tool_failure"),
            ]:
                result = runtime.execute(
                    ["bash", "-c", body],
                    pathlib.Path(tmp) / "log",
                    os.environ.copy(),
                    5,
                )
                assert result["outcome"] == outcome

    def test_retention_removes_oldest_completed_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            old, recent, active = [
                root / name for name in ("pass-old", "pass-recent", "pass-active")
            ]
            for path in (old, recent, active):
                path.mkdir()
                (path / "evidence").write_bytes(b"x" * 100)
            os.utime(old, (1, 1))
            runtime.retain(root, active, 7, 150)
            assert not old.exists()
            assert not recent.exists()
            assert active.exists()

    def test_retention_preserves_runtime_certificate_and_source_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            active = root / "pass-active"
            active.mkdir()
            certificate = root / "mitm-ca"
            certificate.mkdir()
            (certificate / "certificate.pem").write_text("private-runtime-certificate")
            os.utime(certificate, (1, 1))
            runtime.retain(root, active, 7, 1)
            assert certificate.exists()

    def test_completed_active_scenario_evidence_expires_by_age(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            active = root / "pass-active"
            active.mkdir()
            scenario = active / "completed"
            scenario.mkdir()
            (scenario / "receipt.json").write_text("{}")
            os.utime(scenario, (1, 1))
            runtime.retain(root, active, 7, 100000)
            assert not scenario.exists()
            assert active.exists()

    def test_completed_active_scenario_evidence_is_evictable_by_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            active = root / "pass-active"
            active.mkdir()
            completed = active / "completed"
            completed.mkdir()
            (completed / "receipt.json").write_text("{}")
            (completed / "screenshot.png").write_bytes(b"x" * 200)
            runtime.retain(root, active, 7, 100)
            assert not completed.exists()
            assert active.exists()

    def test_atomic_receipt_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "receipt.json"
            runtime.atomic_json(path, {"status": "interrupted"})
            assert path.stat().st_mode & 511 == 384
            assert json.loads(path.read_text())["status"] == "interrupted"

    def test_monitor_stops_descendants_when_private_evidence_fills(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "scenario.log"

            def monitor():
                if log.stat().st_size > 100:
                    return "evidence_failure"
                return None

            result = runtime.execute(
                ["bash", "-c", "while true; do printf '%0100d\\n' 1; sleep 0.01; done"],
                log,
                os.environ.copy(),
                5,
                monitor=monitor,
            )
            assert result["outcome"] == "evidence_failure"
            assert result["completed"] - result["started"] < 2

    def test_retention_handles_disappearing_atomic_write_temporary(self):
        temporary = Mock()
        temporary.is_file.return_value = True
        temporary.is_symlink.return_value = False
        temporary.stat.side_effect = FileNotFoundError()
        with patch.object(pathlib.Path, "rglob", return_value=[temporary]):
            assert runtime.detail_size(pathlib.Path("/synthetic")) == 0


if __name__ == "__main__":
    unittest.main()
