#!/usr/bin/env bash
# Deterministically validate locale output without invoking a language model.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/validate-translations.sh --staged
  scripts/validate-translations.sh --base <commit> --head <commit>

--staged validates only locale files changed in the index, so an English-only
commit can reach the governed translation workflow. --base/--head validates
every locale counterpart affected by that exact English source range and
rejects model changes outside those counterparts.
EOF
}

mode=""
base_ref=""
head_ref=""
while [ "$#" -gt 0 ]; do
  case "$1" in
  --staged)
    [ -z "$mode" ] || {
      echo "[i18n] choose exactly one validation mode" >&2
      exit 2
    }
    mode=staged
    shift
    ;;
  --base | --head)
    [ "$#" -ge 2 ] || {
      echo "[i18n] $1 requires a value" >&2
      exit 2
    }
    mode=range
    case "$1" in
    --base) base_ref=$2 ;;
    --head) head_ref=$2 ;;
    esac
    shift 2
    ;;
  --help | -h)
    usage
    exit 0
    ;;
  *)
    echo "[i18n] unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
  esac
done

case "$mode" in
staged)
  [ -z "$base_ref$head_ref" ] || {
    echo "[i18n] --staged does not accept range options" >&2
    exit 2
  }
  ;;
range)
  [ -n "$base_ref" ] && [ -n "$head_ref" ] || {
    echo "[i18n] range validation requires --base and --head" >&2
    exit 2
  }
  git rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null || {
    echo "[i18n] base does not resolve to a commit: $base_ref" >&2
    exit 2
  }
  git rev-parse --verify --quiet "${head_ref}^{commit}" >/dev/null || {
    echo "[i18n] head does not resolve to a commit: $head_ref" >&2
    exit 2
  }
  ;;
*)
  usage >&2
  exit 2
  ;;
esac

command -v python3 >/dev/null 2>&1 || {
  echo "[i18n] python3 is required" >&2
  exit 1
}

python3 - "$mode" "$base_ref" "$head_ref" <<'PY'
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

MODE, BASE, HEAD = sys.argv[1:]
LOCALES = (
    "fr", "es", "de", "pt-br", "ja", "ko", "zh-cn", "zh-tw",
    "ar", "it", "hi", "th",
)
SOURCE_RE = re.compile(r"^(docs|src/content/docs)/en/(.+\.mdx?)$")
TARGET_RE = re.compile(
    r"^(docs|src/content/docs)/(fr|es|de|pt-br|ja|ko|zh-cn|zh-tw|ar|it|hi|th)/(.+\.mdx?)$"
)


def git(*args: str, check: bool = True) -> bytes:
    result = subprocess.run(
        ["git", *args], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def name_status(*args: str) -> list[tuple[str, str]]:
    fields = git("diff", "--name-status", "--no-renames", "-z", *args).split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        raise RuntimeError("git returned malformed name-status output")
    return [
        (fields[index].decode(), fields[index + 1].decode("utf-8", "strict"))
        for index in range(0, len(fields), 2)
    ]


def index_bytes(path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f":{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return result.stdout if result.returncode == 0 else None


def frontmatter(raw: bytes, path: str) -> str:
    text = raw.decode("utf-8", "strict")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError(f"{path}: missing opening YAML frontmatter delimiter")
    try:
        end = next(index for index, line in enumerate(lines[1:], 1) if line.strip() == "---")
    except StopIteration as exc:
        raise ValueError(f"{path}: missing closing YAML frontmatter delimiter") from exc
    return "\n".join(lines[1:end])


def metadata(raw: bytes, path: str) -> tuple[str, str]:
    header = frontmatter(raw, path)
    hashes = re.findall(
        r'^\s*sourceHash:\s*["\']?([0-9a-f]{12})["\']?\s*$', header, re.MULTILINE
    )
    translators = re.findall(
        r'^\s*translator:\s*["\']?([^"\'\s]+)["\']?\s*$', header, re.MULTILINE
    )
    if len(hashes) != 1:
        raise ValueError(f"{path}: expected exactly one 12-hex i18n.sourceHash")
    if translators != ["machine"]:
        raise ValueError(f"{path}: expected exactly one i18n translator set to machine")
    return hashes[0], translators[0]


def without_frontmatter(text: str) -> str:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return text
    for index, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            return "".join(lines[index + 1 :])
    return text


PROSE_JSX_ATTRIBUTES = ("title", "text", "alt")
PROSE_JSX_ATTRIBUTE_RE = re.compile(
    r"(?<![-A-Za-z0-9_:.])(" + "|".join(PROSE_JSX_ATTRIBUTES)
    + r")\s*=\s*(?:\"[^\"\n]*\"|'[^'\n]*')"
)
FENCE_RE = re.compile(
    r"(?ms)^\s*(?P<f>`{3,}|~{3,})(?P<info>[^\n]*)\n.*?^\s*(?P=f)\s*$"
)
MDX_TAG_RE = re.compile(
    r"(?s)</?[A-Z][A-Za-z0-9_.:-]*(?:\s+[^<>]*?)?/?>"
)


def normalize_mdx_tag(tag: str) -> str:
    return PROSE_JSX_ATTRIBUTE_RE.sub(
        lambda match: f"{match.group(1)}=<translated>", tag
    )


def protected_fragments(raw: bytes) -> dict[str, list[str]]:
    body = without_frontmatter(raw.decode("utf-8", "strict"))
    body_without_fences = FENCE_RE.sub("", body)
    return {
        "fence signatures": [
            match.group("info").strip() for match in FENCE_RE.finditer(body)
        ],
        "URLs": re.findall(r"https?://[^\s<>\]\)\"']+", body_without_fences),
        "link targets": re.findall(r"\]\(([^)]+)\)", body_without_fences),
        "MDX imports/exports": re.findall(
            r"(?m)^(?:import|export)\s+.*$", body_without_fences
        ),
        "MDX component tags": [
            normalize_mdx_tag(match.group(0))
            for match in MDX_TAG_RE.finditer(body_without_fences)
        ],
    }


def describe_fragment_drift(source_values: list[str], target_values: list[str]) -> str:
    details = []
    source_counts = Counter(source_values)
    target_counts = Counter(target_values)
    for direction, drift in (
        ("missing", source_counts - target_counts),
        ("unexpected", target_counts - source_counts),
    ):
        items = sorted(drift.items())
        for value, count in items[:3]:
            details.append(f"{direction} {value!r} (count {count})")
        if len(items) > 3:
            details.append(f"{direction} {len(items) - 3} more fragment kinds")
    if not details:
        for index, (source_value, target_value) in enumerate(
            zip(source_values, target_values), 1
        ):
            if source_value != target_value:
                details.append(
                    f"position {index} expected {source_value!r}, got {target_value!r}"
                )
                break
    return "; ".join(details)


def validate_target(source_raw: bytes, target_raw: bytes, target: str) -> None:
    expected = hashlib.sha256(source_raw).hexdigest()[:12]
    actual, _translator = metadata(target_raw, target)
    if actual != expected:
        raise ValueError(
            f"{target}: stale sourceHash (stored={actual}, expected={expected})"
        )
    source_fragments = protected_fragments(source_raw)
    target_fragments = protected_fragments(target_raw)
    for category, values in source_fragments.items():
        if target_fragments[category] != values:
            drift = describe_fragment_drift(values, target_fragments[category])
            raise ValueError(f"{target}: protected {category} changed: {drift}")


def counterparts(source_path: str) -> list[str]:
    match = SOURCE_RE.fullmatch(source_path)
    if not match:
        return []
    root, relative = match.groups()
    return [f"{root}/{locale}/{relative}" for locale in LOCALES]


def changed_target_paths(raw: bytes) -> set[str]:
    targets: set[str] = set()
    for path in raw.split(b"\0"):
        if not path:
            continue
        decoded = path.decode("utf-8", "strict")
        if TARGET_RE.fullmatch(decoded):
            targets.add(decoded)
    return targets


errors: list[str] = []

if MODE == "staged":
    for status, target in name_status("--cached"):
        match = TARGET_RE.fullmatch(target)
        if not match:
            continue
        root, _locale, relative = match.groups()
        source = f"{root}/en/{relative}"
        source_raw = index_bytes(source)
        target_raw = index_bytes(target)
        try:
            if status.startswith("D"):
                if source_raw is not None:
                    raise ValueError(f"{target}: cannot delete translation while {source} exists")
                continue
            if source_raw is None:
                raise ValueError(f"{target}: English source is missing from the index")
            if target_raw is None:
                raise ValueError(f"{target}: staged translation content is unavailable")
            validate_target(source_raw, target_raw, target)
        except (UnicodeError, ValueError) as exc:
            errors.append(str(exc))
else:
    changed_sources: dict[str, str] = {}
    for status, source in name_status(f"{BASE}...{HEAD}", "--", "docs/en", "src/content/docs/en"):
        if SOURCE_RE.fullmatch(source):
            changed_sources[source] = status[0]

    expected_targets = {
        target for source in changed_sources for target in counterparts(source)
    }
    changed_targets = changed_target_paths(
        git("diff", "--name-only", "-z", f"{BASE}...{HEAD}")
    )
    changed_targets.update(changed_target_paths(git("diff", "--name-only", "-z", HEAD)))
    changed_targets.update(
        changed_target_paths(git("ls-files", "--others", "--exclude-standard", "-z"))
    )
    for changed in sorted(changed_targets - expected_targets):
        errors.append(f"{changed}: output is not a counterpart of changed English source")

    for source, status in sorted(changed_sources.items()):
        source_file = Path(source)
        targets = counterparts(source)
        if status == "D" or not source_file.exists():
            for target in targets:
                if Path(target).exists():
                    errors.append(f"{target}: orphan remains after deleting {source}")
            continue
        try:
            source_raw = source_file.read_bytes()
        except OSError as exc:
            errors.append(f"{source}: cannot read source: {exc}")
            continue
        for target in targets:
            try:
                target_raw = Path(target).read_bytes()
                validate_target(source_raw, target_raw, target)
            except FileNotFoundError:
                errors.append(f"{target}: missing translation for {source}")
            except (OSError, UnicodeError, ValueError) as exc:
                errors.append(str(exc))

if errors:
    for error in errors:
        print(f"[i18n] {error}", file=sys.stderr)
    print(f"[i18n] validation failed with {len(errors)} error(s)", file=sys.stderr)
    raise SystemExit(1)

print("[i18n] deterministic translation validation passed")
PY
