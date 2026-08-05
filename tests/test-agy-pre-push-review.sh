#!/usr/bin/env bash
# Hermetic tests for the Antigravity-only local review gate.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
PRE_PUSH="$REPO_ROOT/scripts/agy-pre-push-review.sh"
REVIEW="$REPO_ROOT/scripts/agy-review.sh"
SCHEMA="$REPO_ROOT/scripts/agy-review-output.schema.json"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  printf '  PASS: %s\n' "$1"
}
fail() {
  FAIL=$((FAIL + 1))
  printf '  FAIL: %s — %s\n' "$1" "$2"
}

setup_repo() {
  rm -rf "${WORK:?}/repo" "${WORK:?}/bin" "$WORK/calls" "$WORK/count"
  mkdir -p "$WORK/repo/scripts" "$WORK/bin"
  git -C "$WORK/repo" init -q
  git -C "$WORK/repo" config user.email test@example.com
  git -C "$WORK/repo" config user.name Test
  cp "$REVIEW" "$SCHEMA" "$PRE_PUSH" "$WORK/repo/scripts/"
  printf 'base\n' >"$WORK/repo/file.txt"
  git -C "$WORK/repo" add .
  git -C "$WORK/repo" commit -qm base
  git -C "$WORK/repo" branch -M main
  git -C "$WORK/repo" switch -qc feature
  printf 'change\n' >>"$WORK/repo/file.txt"
  git -C "$WORK/repo" commit -qam change
  cat >"$WORK/bin/agy" <<'SH'
#!/bin/sh
count=0
[ ! -f "$FAKE_AGY_COUNT" ] || count=$(cat "$FAKE_AGY_COUNT")
count=$((count + 1))
printf '%s\n' "$count" >"$FAKE_AGY_COUNT"
{
  printf '%s\n' "--- call $count ---"
  printf '%s\n' "$@"
  printf 'active=%s prepush=%s gateway=%s github=%s\n' \
    "${AGY_REVIEW_ACTIVE:-}" "${AGY_PRE_PUSH_REVIEW_ACTIVE:-}" \
    "${GATEWAY_TOKEN:-}" "${GITHUB_TOKEN:-}"
} >>"$FAKE_AGY_CALLS"
if [ -n "${FAKE_AGY_BUNDLE_CAPTURE:-}" ]; then
  for review_bundle in "$PWD"/.agy-review.*/code-review-target.txt; do
    if [ -f "$review_bundle" ]; then
      cp "$review_bundle" "$FAKE_AGY_BUNDLE_CAPTURE"
    fi
  done
fi
if [ "${FAKE_AGY_MALFORMED_CALL:-0}" -eq "$count" ]; then
  printf 'not-json\n'
elif [ "${FAKE_AGY_BLOCK_CALL:-0}" -eq "$count" ]; then
  printf '%s\n' '{"event":"result","result":{"status":"SUCCESS","structured_output":{"verdict":"needs-attention","summary":"blocking finding","findings":[{"severity":"high","title":"bug","body":"redacted evidence","file":"file.txt","line_start":1,"line_end":1,"confidence":1,"recommendation":"fix it"}],"next_steps":["fix"]}}}'
else
  printf '%s\n' '{"event":"result","result":{"status":"SUCCESS","structured_output":{"verdict":"approve","summary":"clean","findings":[],"next_steps":[]}}}'
fi
SH
  chmod +x "$WORK/bin/agy"
}

run_review() {
  local path=$1 rc=0
  shift
  (
    unset AGY_REVIEW_ACTIVE AGY_PRE_PUSH_REVIEW_ACTIVE
    cd "$WORK/repo"
    PATH="$path" FAKE_AGY_CALLS="$WORK/calls" FAKE_AGY_COUNT="$WORK/count" \
      AGY_REVIEW_BASE_REF=main "$@" bash scripts/agy-pre-push-review.sh
  ) >"$WORK/output" 2>&1 || rc=$?
  return "$rc"
}

echo "Antigravity local review tests"
setup_repo
if run_review "$WORK/bin:$PATH" env GATEWAY_TOKEN=private GITHUB_TOKEN=private \
  FAKE_AGY_BUNDLE_CAPTURE="$WORK/review-bundle" &&
  [ "$(cat "$WORK/count")" -eq 2 ] &&
  [ "$(grep -c -- '--sandbox' "$WORK/calls")" -eq 2 ] &&
  [ "$(grep -c -- 'Gemini 3.6 Flash (High)' "$WORK/calls")" -eq 2 ] &&
  ! grep -q -- '--effort' "$WORK/calls" &&
  [ "$(grep -c -- '--json-schema' "$WORK/calls")" -eq 2 ] &&
  ! grep -q -- '--dangerously-skip-permissions' "$WORK/calls" &&
  grep -q 'active=1 prepush=1 gateway= github=' "$WORK/calls" &&
  grep -q 'dedicated semantic PII audit' "$WORK/calls" &&
  grep -q 'Do not execute repository test' "$WORK/calls" &&
  grep -q 'consumer_shell_tests.profiles' "$WORK/calls" &&
  grep -q 'second independent Antigravity verifier' "$WORK/calls" &&
  grep -q 'code-review-target.txt' "$WORK/calls" &&
  grep -q 'Do not run terminal commands' "$WORK/calls" &&
  ! grep -q 'Inspect git diff --find-renames' "$WORK/calls" &&
  grep -q '^commit ' "$WORK/review-bundle" &&
  grep -q '^+change$' "$WORK/review-bundle" &&
  grep -q 'gate passed' "$WORK/output"; then
  pass "two schema-validated Flash passes review a precomputed bundle without inherited credentials"
else
  fail "clean branch receives two independent Antigravity passes" "$(cat "$WORK/output")"
fi

setup_repo
if run_review "$WORK/bin:$PATH" env FAKE_AGY_BLOCK_CALL=2; then
  fail "verified high finding blocks" "review returned success"
elif [ "$?" -eq 3 ] && grep -q 'gate blocked' "$WORK/output"; then
  pass "critical/high finding from either pass blocks the gate"
else
  fail "verified high finding blocks" "$(cat "$WORK/output")"
fi

setup_repo
if run_review "$WORK/bin:$PATH" env FAKE_AGY_MALFORMED_CALL=1; then
  fail "malformed provider output blocks" "review returned success"
elif grep -q 'malformed or incomplete' "$WORK/output"; then
  pass "malformed provider output fails closed"
else
  fail "malformed provider output fails closed" "$(cat "$WORK/output")"
fi

setup_repo
printf 'dirty\n' >>"$WORK/repo/file.txt"
if run_review "$WORK/bin:$PATH" env; then
  fail "dirty branch is rejected" "review returned success"
elif [ ! -e "$WORK/count" ] && grep -q 'exact branch' "$WORK/output"; then
  pass "dirty branch is rejected before a model call"
else
  fail "dirty branch is rejected before a model call" "$(cat "$WORK/output")"
fi

setup_repo
if run_review "/usr/bin:/bin" env; then
  fail "missing agy blocks" "review returned success"
elif grep -q 'required command is unavailable: agy' "$WORK/output"; then
  pass "missing Antigravity blocks review"
else
  fail "missing Antigravity blocks review" "$(cat "$WORK/output")"
fi

setup_repo
git -C "$WORK/repo" switch -q main
if run_review "$WORK/bin:$PATH" env && [ ! -e "$WORK/count" ]; then
  pass "branch with no diff exits without a model call"
else
  fail "branch with no diff exits without a model call" "$(cat "$WORK/output")"
fi

setup_repo
rc=0
(
  cd "$WORK/repo"
  PATH="$WORK/bin:$PATH" FAKE_AGY_CALLS="$WORK/calls" FAKE_AGY_COUNT="$WORK/count" \
    AGY_REVIEW_ACTIVE=1 bash scripts/agy-pre-push-review.sh
) >"$WORK/output" 2>&1 || rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$WORK/count" ] && grep -q 'nested.*refused' "$WORK/output"; then
  pass "recursive review is rejected before another model call"
else
  fail "recursive review is rejected" "rc=$rc; $(cat "$WORK/output")"
fi

printf '\nResults: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
