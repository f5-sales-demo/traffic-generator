"""Execute the video scenario and require conversion after every parameter update."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_video_scenario_calls_native_conversion_for_each_payload(tmp_path):
    curl = tmp_path / "curl"
    curl.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://'))
method = args[args.index('-X')+1] if '-X' in args else 'GET'
with pathlib.Path(os.environ['CALL_LOG']).open('a') as stream:
    stream.write(json.dumps({'url':url,'method':method})+'\\n')
if url.endswith('/auth/login'):
    print(json.dumps({'token':'synthetic.token'}))
elif '/mailhog/' in url:
    print(json.dumps({'items':[]}))
elif url.endswith('/videos') and method=='POST':
    print(json.dumps({'id':42})+'\\n200')
elif '/convert_video?' in url:
    print(json.dumps({'message':'Video conversion command executed.','status':200})+'\\n200')
elif method=='PUT':
    print(json.dumps({'id':42})+'\\n200')
elif '-w' in args:
    print('200')
else:
    print('{}')
""")
    curl.chmod(0o700)
    sleep = tmp_path / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o700)
    calls = tmp_path / "calls.jsonl"
    environment = dict(
        os.environ,
        PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
        TARGET_PROTOCOL="https",
        CRAPI_BASE_URL="https://example.test/crapi",
        CALL_LOG=str(calls),
    )
    environment.pop("TGEN_FIXTURES", None)
    result = subprocess.run(  # noqa: S603 - owned script with deterministic synthetic APIs
        [
            "/bin/bash",
            str(ROOT / "suites/crapi-exploits/13-command-injection-video.sh"),
            "example.test",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    actions = [json.loads(line) for line in calls.read_text().splitlines()]
    workflow = [
        action
        for action in actions
        if action["method"] == "PUT" or "convert_video?" in action["url"]
    ]
    assert [action["method"] for action in workflow] == ["PUT", "GET"] * 3
    assert all(
        action["url"].endswith("video_id=42")
        for action in workflow
        if action["method"] == "GET"
    )
    catalog = json.loads((ROOT / "suites/catalog.json").read_text())
    scenario = next(
        item
        for item in catalog["scenarios"]
        if item["id"] == "crapi-exploits/13-command-injection-video"
    )
    trigger = next(
        item
        for item in scenario["dispatch_contract"]["requirements"]
        if item["id"] == "video-conversion-trigger"
    )
    assert trigger["minimum_dispatches"] == 3
    assert trigger["response_contract_by_status"]["500"]["json_equals"]["status"] == 500
