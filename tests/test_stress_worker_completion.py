"""A completed stress parent must await native and nested worker results."""

import json
import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("child_exit", [0, 1])
def test_origin_stress_waits_for_child_completion(tmp_path, child_exit):
    suites = tmp_path / "suites"
    cdn = suites / "cdn-load-testing"
    cdn.mkdir(parents=True)
    script = cdn / "09-origin-torture.sh"
    shutil.copyfile(ROOT / "suites/cdn-load-testing/09-origin-torture.sh", script)
    (suites / "dvga-exploits").mkdir()
    for name in (
        "_graphql-torture.lua",
        "_restaurant-torture.lua",
        "_crapi-torture.lua",
    ):
        (cdn / name).write_text("-- development fixture")
    runner = suites / "runner.sh"
    runner.write_text(
        '#!/bin/sh\nmkdir -p "$TGEN_RESULTS_DIR"\n/bin/sleep 1.5\nprintf finished > "$TGEN_RESULTS_DIR/child-finished"\nexit '
        + str(child_exit)
        + "\n"
    )
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("wrk", "hey", "ab", "vegeta"):
        tool = tools / name
        tool.write_text(
            "#!/bin/sh\n/bin/sleep 0.2\nprintf 'Requests/sec: 2\\nLatency 1ms\\n'\n"
        )
        tool.chmod(0o700)
    for name, output in (("curl", "200"), ("ss", "estab 0"), ("sleep", "")):
        tool = tools / name
        tool.write_text("#!/bin/sh\nprintf '%s' '" + output + "'\n")
        tool.chmod(0o700)
    results = tmp_path / "results"
    result = subprocess.run(  # noqa: S603 - owned shell with deterministic native/child fixtures
        ["/bin/bash", str(script), "www.example.test"],
        env=dict(
            os.environ,
            PATH=str(tools) + os.pathsep + os.environ["PATH"],
            TGEN_INHERITED_BOUNDARY="1",
            TGEN_DURATION="1",
            TGEN_RESULTS_DIR=str(results),
            TARGET_PROTOCOL="https",
        ),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert (results / "nested-dvga-exploits/child-finished").read_text() == "finished"
    assert result.returncode == child_exit, result.stdout + result.stderr


def test_stress_duration_and_native_actions_cannot_be_shortened():
    catalog = json.loads((ROOT / "suites/catalog.json").read_text())
    kraken = next(
        item
        for item in catalog["scenarios"]
        if item["id"] == "cdn-load-testing/08-kraken-cdn-max"
    )
    assert kraken["duration_seconds"] == 600
    assert {item["id"] for item in kraken["dispatch_contract"]["requirements"]} >= {
        "scheduled-herd-burst",
        "mixed-post",
        "mixed-put",
        "lua-client-diversity",
    }
    assert {item["tool"] for item in kraken["tool_contract"]["requirements"]} == {
        "wrk",
        "hey",
        "vegeta",
        "ab",
    }


def test_kraken_workers_preserve_reports_and_response_deadlines():
    source = (ROOT / "suites/cdn-load-testing/08-kraken-cdn-max.sh").read_text()
    assert source.count('hey -z "${DURATION}s" -t 60') == 4
    assert source.count('ab -l -n "${TGEN_REQUESTS:-999999}"') == 2
    assert '-k -t "$DURATION"' not in source
    assert "$RESULTS_DIR/hey-${STAMP}.log" in source
