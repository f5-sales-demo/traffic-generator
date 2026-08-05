#!/usr/bin/env bash
# Canonical pre-push entrypoint for the Antigravity-only branch review gate.
set -euo pipefail

if [ "${AGY_PRE_PUSH_REVIEW_ACTIVE:-}" = "1" ] || [ "${AGY_REVIEW_ACTIVE:-}" = "1" ]; then
  echo "[review] nested Antigravity pre-push review refused" >&2
  exit 1
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "[review] must run inside a git repository" >&2
  exit 1
}
base_ref=${AGY_REVIEW_BASE_REF:-origin/main}

AGY_PRE_PUSH_REVIEW_ACTIVE=1 \
  bash "$repo_root/scripts/agy-review.sh" code --base "$base_ref"
