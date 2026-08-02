#!/usr/bin/env bash
# Lint MDX prose with the same two linters that own Markdown prose.
#
# WHY THIS EXISTS
# Neither linter can see .mdx on its own:
#   * pre-commit's markdownlint hook selects `types: [markdown]`, and `identify`
#     tags .mdx as `mdx`, not `markdown`.
#   * Super-Linter v8.7.0 routes only the `md` extension into its MARKDOWN and
#     NATURAL_LANGUAGE file arrays (lib/functions/buildFileList.sh).
# A repository whose documentation is .mdx therefore passes both gates without
# either linter having opened a file. See docs-control#847.
#
# Scope matches Super-Linter's own posture (VALIDATE_ALL_CODEBASE=false): callers
# pass the files that changed, so enabling this does not red-light every
# repository at once — a pull request is judged on the pages it touches.
#
# Usage:
#   lint-mdx-prose.sh [PATH ...]         lint the named files (.mdx are selected)
#   lint-mdx-prose.sh --changed [BASE]   lint .mdx changed against BASE (default origin/main)
#   lint-mdx-prose.sh --textlint-only [PATH ...]
#       Run only textlint, and accept .md as well as .mdx. This is the local
#       pre-commit path for plain Markdown: CI lints .md prose through
#       Super-Linter's NATURAL_LANGUAGE, which has no local equivalent, so a
#       terminology finding would otherwise only surface after a full CI run.
#       markdownlint is skipped here because the markdownlint hook already owns
#       .md locally.
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

# Pinned to the exact versions Super-Linter v8.7.0 ships in its container
# (super-linter/super-linter dependencies/package.json), so .md judged inside the
# container and .mdx judged here cannot disagree about what is a finding. Bump
# these in the same commit that bumps the Super-Linter SHA.
#
# Note the tool family: Super-Linter runs markdownlint-cli, not markdownlint-cli2.
MARKDOWNLINT_PKG="markdownlint-cli@0.49.1"
TEXTLINT_PKG="textlint@15.7.0"
TEXTLINT_PLUGIN_PKG="textlint-plugin-mdx@1.0.1"
TEXTLINT_RULE_PKG="textlint-rule-terminology@5.2.16"

# Test seams. Left unset in normal use so the pinned versions above are the only
# ones that ever run — preferring a binary from PATH would let a developer's
# locally-installed version disagree with CI, which is the drift this pinning
# exists to prevent.
MARKDOWNLINT_BIN="${MDX_LINT_MARKDOWNLINT_BIN:-}"
TEXTLINT_BIN="${MDX_LINT_TEXTLINT_BIN:-}"

collect_changed() {
  local base="${1:-origin/main}"
  git diff --name-only --diff-filter=ACMR "${base}...HEAD" 2>/dev/null ||
    git diff --name-only --diff-filter=ACMR "$base" 2>/dev/null ||
    true
}

main() {
  local textlint_only=0
  if [ "${1:-}" = "--textlint-only" ]; then
    textlint_only=1
    shift
  fi

  local -a candidates=()
  if [ "${1:-}" = "--changed" ]; then
    shift
    while IFS= read -r line; do
      [ -n "$line" ] && candidates+=("$line")
    done < <(collect_changed "${1:-origin/main}")
  else
    candidates=("$@")
  fi

  # In the default mode .md is excluded: Super-Linter already lints that extension
  # in CI, and linting it here too would report every finding twice. In
  # --textlint-only mode .md is included, because that mode exists precisely to
  # give plain Markdown a local textlint run it otherwise never gets.
  local -a files=()
  local f
  for f in "${candidates[@]:-}"; do
    case "$f" in
    *.mdx) [ -f "$f" ] && files+=("$f") ;;
    *.md) [ "$textlint_only" -eq 1 ] && [ -f "$f" ] && files+=("$f") ;;
    esac
  done

  local selection=".mdx"
  [ "$textlint_only" -eq 1 ] && selection=".md/.mdx"

  if [ "${#files[@]}" -eq 0 ]; then
    echo "No ${selection} files to lint."
    return 0
  fi

  echo "Linting ${#files[@]} ${selection} file(s)."

  local rc=0

  if [ "$textlint_only" -eq 0 ]; then
    local -a markdownlint_cmd
    if [ -n "$MARKDOWNLINT_BIN" ]; then
      markdownlint_cmd=("$MARKDOWNLINT_BIN")
    else
      markdownlint_cmd=(npx --yes "$MARKDOWNLINT_PKG")
    fi
    local -a markdownlint_args=()
    [ -f "${REPO_ROOT}/.markdownlint.json" ] && markdownlint_args+=(--config "${REPO_ROOT}/.markdownlint.json")
    "${markdownlint_cmd[@]}" "${markdownlint_args[@]}" "${files[@]}" || rc=1
  fi

  # --plugin mdx is not optional: without it textlint parses MDX as Markdown and
  # reports the JSX as prose.
  local -a textlint_cmd
  if [ -n "$TEXTLINT_BIN" ]; then
    textlint_cmd=("$TEXTLINT_BIN")
  else
    textlint_cmd=(npx --yes -p "$TEXTLINT_PKG" -p "$TEXTLINT_RULE_PKG" -p "$TEXTLINT_PLUGIN_PKG" textlint)
  fi
  local -a textlint_args=(--plugin mdx -f compact)
  [ -f "${REPO_ROOT}/.textlintrc" ] && textlint_args+=(-c "${REPO_ROOT}/.textlintrc")
  "${textlint_cmd[@]}" "${textlint_args[@]}" "${files[@]}" || rc=1

  return "$rc"
}

main "$@"
