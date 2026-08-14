#!/usr/bin/env bash
# Rejects two classes of committed content that break on any machine but the one
# that produced them:
#
#   1. Tracked symlinks with an absolute target. A clone lands a dangling link,
#      and tooling that follows it fails in ways that look unrelated to the cause.
#   2. A user's home directory hardcoded in a tracked file.
#
# Both slip past the usual gates: `.gitignore` patterns ending in `/` match only
# directories, so a symlink of an ignored name is still staged, and CI often
# masks a dangling link by creating the real thing (npm ci, pip install).
#
# The symlink check runs by default. The home-directory scan is opt-in via
# --include-paths, because measuring it across all 38 governed repositories flagged
# 10 of them and only 2 findings were real: the rest were API routes (/Users/1),
# URL paths (/home/index), shell variables (/home/${USERNAME}), placeholder names,
# and upstream-generated specification examples. A gate that is ~80% false positives
# gets switched off, which is worse than not having it.
#
# Run from any repo root:
#   bash scripts/check-repo-hygiene.sh                  # symlinks only (the gate)
#   bash scripts/check-repo-hygiene.sh --include-paths   # also scan for home dirs
# Exit 0 = clean, Exit 1 = violations found.
#
# To allow a deliberate example path, put `repo-hygiene:allow` on the same line.
set -euo pipefail

VIOLATIONS=0
INCLUDE_PATHS=0

for arg in "$@"; do
  case "$arg" in
  --include-paths) INCLUDE_PATHS=1 ;;
  -h | --help)
    sed -n '2,20p' "$0"
    exit 0
    ;;
  *)
    echo "::error::unknown argument: ${arg}" >&2
    exit 1
    ;;
  esac
done

# Placeholder user names are portable documentation, not a machine-specific path.
PLACEHOLDERS='you|user|users|username|userid|your-user|your_username|me|example|alice|bob|USERNAME|<user>|<username>|<you>|<your-user>|\.\.\.'

# Any path built from a variable is portable by construction.
VARIABLE_FORMS='^\$|^\{|\$\{|^%[A-Za-z_]+%$'

# Home directories owned by a CI runner are the same on every machine.
CI_USERS='runner|circleci|travis|vsts|ubuntu|node|jenkins|gitpod|vscode'

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "::error::not a git repository — cannot inspect tracked files"
  exit 1
fi

# Absolute targets, and relative targets that climb out of the repository, both
# break on a fresh clone. Resolved lexically: no filesystem access, so a dangling
# link is judged the same as a live one.
symlink_escapes() {
  local link_path="$1" target="$2" dir depth=0 segment
  case "$target" in
  /* | [A-Za-z]:[\\/]* | \\\\*) return 0 ;;
  esac
  dir=$(dirname "$link_path")
  [ "$dir" = "." ] && dir=""
  while [ -n "$dir" ]; do
    case "$dir" in
    */*)
      segment=${dir%%/*}
      dir=${dir#*/}
      ;;
    *)
      segment=$dir
      dir=""
      ;;
    esac
    [ -n "$segment" ] && depth=$((depth + 1))
  done
  while [ -n "$target" ]; do
    case "$target" in
    */*)
      segment=${target%%/*}
      target=${target#*/}
      ;;
    *)
      segment=$target
      target=""
      ;;
    esac
    case "$segment" in
    "" | .) ;;
    ..)
      depth=$((depth - 1))
      [ "$depth" -lt 0 ] && return 0
      ;;
    *) depth=$((depth + 1)) ;;
    esac
  done
  return 1
}

# ---------------------------------------------------------------------------
# 1. Tracked symlinks with an absolute target (git mode 120000; the blob's
#    contents are the link target).
#
#    `git ls-files -s -z` emits "<mode> <sha> <stage>\t<path>\0", so the path is
#    everything after the first tab and survives spaces verbatim. Splitting on
#    whitespace instead would corrupt such a path, and the lookup would then fail
#    silently — reporting a real violation as clean.
# ---------------------------------------------------------------------------
while IFS= read -r -d '' entry; do
  [ -n "$entry" ] || continue
  case "$entry" in 120000\ *) ;; *) continue ;; esac
  path=${entry#*$'\t'}
  if ! target=$(git cat-file blob ":${path}" 2>/dev/null); then
    # Fail closed: a symlink we cannot read is not a symlink we can clear.
    echo "::error file=${path}::tracked symlink could not be read — cannot verify its target"
    VIOLATIONS=$((VIOLATIONS + 1))
    continue
  fi
  if symlink_escapes "$path" "$target"; then
    echo "::error file=${path}::tracked symlink points outside the repository: ${target}"
    echo "  A clone lands a dangling link here. Remove it (git rm --cached '${path}') and"
    echo "  ignore it with a pattern that has no trailing slash, so a symlink is matched too."
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done < <(git ls-files -s -z)

# ---------------------------------------------------------------------------
# 2. Home directories hardcoded in tracked files.
#
#    Each matched path is judged on its own. Judging a whole line would let an
#    allowed path launder a real one beside it, e.g.
#    "PATH=/home/runner/bin:/home/alice/bin".
# ---------------------------------------------------------------------------
CANDIDATE='(/Users/|/home/|[A-Za-z]:\\+Users\\+|\\\\+[A-Za-z0-9._-]+\\+Users\\+)[A-Za-z0-9._${}<>-]+'

path_is_allowed() {
  local candidate="$1" user
  user=${candidate##*/}
  user=${user##*\\}
  # A purely numeric segment is an identifier in a URL or API path, not a person.
  case "$user" in
  '' | *[!0-9]*) ;;
  *) return 0 ;;
  esac
  # A path built from a variable is portable by construction.
  if printf '%s' "$user" | grep -qE "$VARIABLE_FORMS"; then
    return 0
  fi
  printf '%s' "$user" | grep -qE "^(${PLACEHOLDERS}|${CI_USERS})$"
}

if [ "$INCLUDE_PATHS" -eq 1 ]; then
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file=${hit%%:*}
    rest=${hit#*:}
    line=${rest%%:*}
    text=${rest#*:}
    case "$text" in *repo-hygiene:allow*) continue ;; esac

    while IFS= read -r candidate; do
      [ -n "$candidate" ] || continue
      if path_is_allowed "$candidate"; then
        continue
      fi
      echo "::error file=${file},line=${line}::hardcoded home directory in a tracked file: ${candidate}"
      echo "  ${text}"
      echo "  Use a relative path, an environment variable, or a placeholder such as /Users/you/."
      echo "  If the literal path is intentional, add repo-hygiene:allow to that line."
      VIOLATIONS=$((VIOLATIONS + 1))
    done < <(printf '%s' "$text" | grep -oE "$CANDIDATE" || true)
  done < <(
    # --cached searches the index, so the working tree is never read: a symlink is
    # matched on its own target text rather than dereferenced, and a dangling link
    # cannot make the scan fail open. Pathspec exclusions keep this script and its
    # test — which necessarily contain the patterns — out of the results.
    git grep --cached --no-color -nIE -e "$CANDIDATE" -- \
      ':!scripts/check-repo-hygiene.sh' \
      ':!tests/test-check-repo-hygiene.sh' ||
      true
  )
fi

if [ "$VIOLATIONS" -gt 0 ]; then
  echo "::error::repo hygiene: ${VIOLATIONS} violation(s) found."
  exit 1
fi

if [ "$INCLUDE_PATHS" -eq 1 ]; then
  echo "repo hygiene: clean (no escaping symlinks, no hardcoded home directories)."
else
  echo "repo hygiene: clean (no escaping symlinks)."
fi
