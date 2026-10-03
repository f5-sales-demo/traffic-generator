"""Record immutable native tool invocation and completion without retaining credentials."""

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def native_binary(tool: str, search_path: str, runtime: Path) -> str:
    """Resolve an executable outside owned receipt wrappers to avoid recursive attribution."""
    for directory in search_path.split(os.pathsep):
        if not directory:
            continue
        candidate = Path(directory) / tool
        if candidate.resolve().is_relative_to(runtime.resolve()):
            continue
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    message = "required native scanner missing"
    raise ValueError(message)


def attributed_arguments(tool: str, arguments: list[str], marker: str) -> list[str]:
    """Add opaque nested attribution without replacing an authentication header."""
    result = list(arguments)
    if not marker:
        return result
    value = "X-TGen-Child: " + marker
    if tool == "zap":
        for key, value in {
            "description": "owned-child-attribution",
            "enabled": "true",
            "matchtype": "REQ_HEADER",
            "matchstr": "X-TGen-Child",
            "regex": "false",
            "replacement": marker,
        }.items():
            result.extend(["-config", "replacer.full_list(0)." + key + "=" + value])
    elif tool == "sqlmap":
        existing = next(
            (index for index, arg in enumerate(result) if arg.startswith("--headers=")),
            None,
        )
        if existing is not None:
            result[existing] += "\n" + value
        else:
            result.append("--headers=" + value)
    elif tool in ("curl", "ffuf", "dalfox"):
        result.extend(["-H", value])
    elif tool == "arjun":
        result.extend(["--headers", value])
    elif tool in ("gobuster", "feroxbuster", "nuclei"):
        result.extend(["-H", value])
    return result


def main() -> int:
    """Execute the resolved native binary and retain only matched action identifiers."""
    binary, tool = sys.argv[1:3]
    arguments = attributed_arguments(
        tool, sys.argv[3:], os.environ.get("TGEN_CHILD_MARKER", "")
    )
    contract = json.loads(os.environ["TGEN_TOOL_CONTRACT"])
    matched = [
        requirement["id"]
        for requirement in contract["requirements"]
        if requirement["tool"] == tool
        and re.search(requirement["argument_regex"], " ".join(arguments))
    ]
    event = {
        "tool": tool,
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "matched_requirements": matched,
        "started": time.time(),
        "completed": False,
    }
    path = Path(os.environ["TGEN_RESULTS_DIR"]) / "tool-events.jsonl"
    with path.open("a") as stream:
        path.chmod(0o600)
        stream.write(json.dumps(event) + "\n")
    result = subprocess.run([binary, *arguments], check=False)  # noqa: S603 - exact resolved installed tool argv
    event.update(completed=True, exit_code=result.returncode, completed_at=time.time())
    with path.open("a") as stream:
        stream.write(json.dumps(event) + "\n")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
