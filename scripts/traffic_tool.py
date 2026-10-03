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


def worker_arguments(tool: str, arguments: list[str], marker: str) -> list[str]:
    """Bind timed native HTTP workers to opaque request receipts without changing payloads."""
    if tool not in {"wrk", "hey", "ab"}:
        return list(arguments)
    if not re.fullmatch(r"[a-z0-9-]{1,80}", marker):
        message = "invalid native worker marker"
        raise ValueError(message)
    if not arguments or not arguments[-1].startswith(("http://", "https://")):
        message = "native worker target must be final argument"
        raise ValueError(message)
    return [*arguments[:-1], "-H", "X-TGen-Worker: " + marker, arguments[-1]]


def nikto_configuration(source: Path, directory: Path, marker: str) -> Path:
    """Use pinned Nikto's supported config interface while preserving native test IDs."""
    if not re.fullmatch(r"[a-z0-9-]{1,80}", marker):
        message = "invalid owned scanner marker"
        raise ValueError(message)
    text = source.read_text()
    if len(re.findall(r"(?m)^USERAGENT=", text)) != 1:
        message = "native Nikto user-agent contract changed"
        raise ValueError(message)
    text = re.sub(r"(?m)^(USERAGENT=.*)$", r"\1 TGen-Child/" + marker, text)
    text = re.sub(r"(?m)^UPDATES=.*$", "UPDATES=no", text)
    path = directory / ("nikto-" + marker + ".conf")
    path.write_text(text)
    path.chmod(0o600)
    return path


def main() -> int:
    """Execute the resolved native binary and retain only matched action identifiers."""
    binary, tool = sys.argv[1:3]
    arguments = attributed_arguments(
        tool, sys.argv[3:], os.environ.get("TGEN_CHILD_MARKER", "")
    )
    if tool == "nikto" and os.environ.get("TGEN_CHILD_MARKER"):
        config = nikto_configuration(
            Path("/etc/nikto/config.txt"),
            Path(os.environ["TGEN_RESULTS_DIR"]),
            os.environ["TGEN_CHILD_MARKER"],
        )
        arguments.extend(["-config", str(config)])
    contract = json.loads(os.environ["TGEN_TOOL_CONTRACT"])
    matched = [
        requirement["id"]
        for requirement in contract["requirements"]
        if requirement["tool"] == tool
        and re.search(requirement["argument_regex"], " ".join(arguments))
    ]
    worker_marker = tool + "-" + str(os.getpid())
    arguments = worker_arguments(tool, arguments, worker_marker)
    event = {
        "worker_marker": worker_marker,
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
