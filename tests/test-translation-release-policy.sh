#!/usr/bin/env bash
# The old release selector is deterministic but has no active generation route.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$REPO_ROOT/scripts/translation-release-policy.sh"
PASS=0
FAIL=0
pass() {
  printf '  PASS: %s\n' "$1"
  PASS=$((PASS + 1))
}
fail() {
  printf '  FAIL: %s — %s\n' "$1" "$2"
  FAIL=$((FAIL + 1))
}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
printf '%s\n' 'v19.2.0' >"$WORK/tags"
if output=$(bash "$SCRIPT" --head-ref release/v20.0.0 --tags-file "$WORK/tags") && grep -qxF 'eligible=true' <<<"$output"; then pass "legacy selector remains deterministic"; else fail "legacy selector remains deterministic" "$output"; fi
if [ ! -e "$REPO_ROOT/.github/workflows/antigravity-translate.yml" ] && [ ! -e "$REPO_ROOT/workflows/antigravity-translate.yml" ]; then pass "no release branch can invoke translation generation"; else fail "no release branch can invoke translation generation" "generator workflow remains"; fi
watcher="$REPO_ROOT/scripts/collect-antigravity-fleet-state.sh"
if [ ! -e "$watcher" ] && [ ! -L "$watcher" ]; then
  pass "no fleet watcher is shipped"
elif [ ! -f "$watcher" ] || [ -L "$watcher" ] || [ ! -r "$watcher" ]; then
  fail "watcher inspection" "a readable regular watcher is required"
elif grep -qE 'antigravity-translate|TRANSLATIONS_ENABLED' "$watcher"; then
  fail "watcher does not consume release eligibility" "active release dispatch remains"
else
  inspection_status=$?
  if [ "$inspection_status" -eq 1 ]; then
    pass "watcher does not consume release eligibility"
  else
    fail "watcher inspection" "inspection failed with status $inspection_status"
  fi
fi
printf '\nResults: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
