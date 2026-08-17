#!/usr/bin/env bash
# Hermetic tests for the Antigravity-only local review gate.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
PRE_PUSH="$REPO_ROOT/scripts/agy-pre-push-review.sh"
REVIEW="$REPO_ROOT/scripts/agy-review.sh"
PROGRESS="$REPO_ROOT/scripts/run-with-progress.sh"
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
  rm -rf "${WORK:?}/repo" "${WORK:?}/bin" "$WORK/calls" "$WORK/count" \
    "$WORK/scenarios" "$WORK/clock" "$WORK/date-count" "$WORK/sleeps"
  mkdir -p "$WORK/repo/scripts" "$WORK/bin" "$WORK/calls" "$WORK/scenarios"
  printf '1000\n' >"$WORK/clock"
  git -C "$WORK/repo" init -q
  git -C "$WORK/repo" config user.email test@example.com
  git -C "$WORK/repo" config user.name Test
  cp "$REVIEW" "$PROGRESS" "$SCHEMA" "$PRE_PUSH" "$WORK/repo/scripts/"
  cat >"$WORK/repo/scripts/run-with-progress.sh" <<'SH'
#!/bin/sh
test "$1" = --phase
phase=$2
shift 2
test "$1" = --
shift
printf '[PROGRESS] component=antigravity phase=%s state=started elapsed_seconds=0 heartbeat_seconds=1 timestamp=fixture\n' "$phase" >&2
"$@"
rc=$?
printf '[PROGRESS] component=antigravity phase=%s state=%s elapsed_seconds=0 heartbeat_seconds=1 timestamp=fixture exit_code=%s\n' \
  "$phase" "$([ "$rc" -eq 0 ] && printf completed || printf failed)" "$rc" >&2
exit "$rc"
SH
  chmod +x "$WORK/repo/scripts/run-with-progress.sh"
  printf 'base\n' >"$WORK/repo/file.txt"
  git -C "$WORK/repo" add .
  git -C "$WORK/repo" commit -qm base
  git -C "$WORK/repo" branch -M main
  git -C "$WORK/repo" switch -qc feature
  printf 'change\n' >>"$WORK/repo/file.txt"
  git -C "$WORK/repo" commit -qam change
  cat >"$WORK/bin/date" <<'SH'
#!/bin/sh
count=0
[ ! -f "$FAKE_DATE_COUNT" ] || count=$(cat "$FAKE_DATE_COUNT")
count=$((count + 1))
printf '%s\n' "$count" >"$FAKE_DATE_COUNT"
if [ -f "$FAKE_DATE_VALUES" ]; then
  value=$(sed -n "${count}p" "$FAKE_DATE_VALUES")
fi
[ -n "${value:-}" ] || value=$(cat "$FAKE_CLOCK")
case "$*" in
  *+%s*) printf '%s\n' "$value" ;;
  *) printf '1970-01-01T00:00:00Z\n' ;;
esac
SH
  cat >"$WORK/bin/sleep" <<'SH'
#!/bin/sh
printf '%s\n' "$1" >>"$FAKE_SLEEP_RECEIPTS"
now=$(cat "$FAKE_CLOCK")
printf '%s\n' "$((now + $1))" >"$FAKE_CLOCK"
SH
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
} >"$FAKE_AGY_CALLS/$count.args"
printf 'GH_TOKEN=%s\nGITHUB_TOKEN=%s\nREPO_SETTINGS_TOKEN=%s\nREPO_SYNC_TOKEN=%s\nGATEWAY_TOKEN=%s\nGATEWAY_URL=%s\n' \
  "${GH_TOKEN:-}" "${GITHUB_TOKEN:-}" "${REPO_SETTINGS_TOKEN:-}" \
  "${REPO_SYNC_TOKEN:-}" "${GATEWAY_TOKEN:-}" "${GATEWAY_URL:-}" \
  >"$FAKE_AGY_CALLS/$count.credentials"
if [ -n "${FAKE_AGY_BUNDLE_CAPTURE:-}" ]; then
  for review_bundle in "$PWD"/.agy-review.*/code-review-target.txt; do
    if [ -f "$review_bundle" ]; then
      cp "$review_bundle" "$FAKE_AGY_BUNDLE_CAPTURE"
    fi
  done
fi
scenario="$FAKE_AGY_QUEUE/$count"
if [ -f "$scenario/elapsed" ]; then
  now=$(cat "$FAKE_CLOCK")
  elapsed=$(cat "$scenario/elapsed")
  printf '%s\n' "$((now + elapsed))" >"$FAKE_CLOCK"
fi
if [ -f "$scenario/stdout" ]; then
  cat "$scenario/stdout"
else
  printf '%s\n' '{"event":"result","result":{"status":"SUCCESS","structured_output":{"verdict":"approve","summary":"clean","findings":[],"next_steps":[]}}}'
fi
if [ -f "$scenario/async-stderr" ]; then
  (/bin/sleep 0.2; cat "$scenario/stderr" >&2) &
elif [ -f "$scenario/stderr" ]; then
  cat "$scenario/stderr" >&2
fi
if [ -f "$scenario/status" ]; then exit "$(cat "$scenario/status")"; fi
SH
  chmod +x "$WORK/bin/agy" "$WORK/bin/date" "$WORK/bin/sleep"
}

queue_scenario() {
  local number=$1 stdout=${2:-} stderr=${3:-} status=${4:-0} elapsed=${5:-0}
  mkdir -p "$WORK/scenarios/$number"
  [ -z "$stdout" ] || printf '%s\n' "$stdout" >"$WORK/scenarios/$number/stdout"
  [ -z "$stderr" ] || printf '%s\n' "$stderr" >"$WORK/scenarios/$number/stderr"
  printf '%s\n' "$status" >"$WORK/scenarios/$number/status"
  printf '%s\n' "$elapsed" >"$WORK/scenarios/$number/elapsed"
}

queue_async_stderr_scenario() {
  queue_scenario "$@"
  : >"$WORK/scenarios/$1/async-stderr"
}

valid_result='{"event":"result","result":{"status":"SUCCESS","structured_output":{"verdict":"approve","summary":"clean","findings":[],"next_steps":[]}}}'
high_result='{"event":"result","result":{"status":"SUCCESS","structured_output":{"verdict":"needs-attention","summary":"blocking finding","findings":[{"severity":"high","title":"bug","body":"redacted evidence","file":"file.txt","line_start":1,"line_end":1,"confidence":1,"recommendation":"fix it"}],"next_steps":["fix"]}}}'
critical_result=${high_result/\"high\"/\"critical\"}

run_review() {
  local path=$1 rc=0
  shift
  (
    unset AGY_REVIEW_ACTIVE AGY_PRE_PUSH_REVIEW_ACTIVE
    cd "$WORK/repo"
    PATH="$path" FAKE_AGY_CALLS="$WORK/calls" FAKE_AGY_COUNT="$WORK/count" \
      FAKE_AGY_QUEUE="$WORK/scenarios" FAKE_CLOCK="$WORK/clock" \
      FAKE_DATE_COUNT="$WORK/date-count" FAKE_DATE_VALUES="$WORK/date-values" \
      FAKE_SLEEP_RECEIPTS="$WORK/sleeps" AGY_REVIEW_BASE_REF=main \
      "$@" bash scripts/agy-pre-push-review.sh
  ) >"$WORK/output" 2>&1 || rc=$?
  return "$rc"
}

echo "Antigravity local review tests"

progress_rc=0
AGY_PROGRESS_INTERVAL_SECONDS=1 GITHUB_STEP_SUMMARY="$WORK/progress-summary" \
  bash "$PROGRESS" --phase fixture-review -- bash -c 'sleep 2' \
  >"$WORK/progress-output" 2>&1 || progress_rc=$?
if [ "$progress_rc" -eq 0 ] &&
  grep -Eq '^\[PROGRESS\] component=antigravity phase=fixture-review state=started elapsed_seconds=0 heartbeat_seconds=1 timestamp=[-0-9TZ:]+$' "$WORK/progress-output" &&
  grep -Eq '^\[PROGRESS\] component=antigravity phase=fixture-review state=running elapsed_seconds=[1-9][0-9]* heartbeat_seconds=1 timestamp=[-0-9TZ:]+$' "$WORK/progress-output" &&
  grep -Eq '^\[PROGRESS\] component=antigravity phase=fixture-review state=completed elapsed_seconds=[1-9][0-9]* heartbeat_seconds=1 timestamp=[-0-9TZ:]+ exit_code=0$' "$WORK/progress-output" &&
  grep -q 'fixture-review.*completed.*exit code.*0' "$WORK/progress-summary"; then
  pass "progress runner emits structured live heartbeats and a durable terminal summary"
else
  fail "progress runner emits structured live heartbeats and a durable terminal summary" \
    "rc=$progress_rc; $(cat "$WORK/progress-output" 2>/dev/null || true)"
fi

progress_rc=0
AGY_PROGRESS_INTERVAL_SECONDS=1 bash "$PROGRESS" --phase fixture-failure -- \
  bash -c 'exit 19' >"$WORK/progress-output" 2>&1 || progress_rc=$?
if [ "$progress_rc" -eq 19 ] &&
  grep -Eq 'phase=fixture-failure state=failed .* exit_code=19$' "$WORK/progress-output"; then
  pass "progress runner preserves failures and reports their terminal state"
else
  fail "progress runner preserves failures and reports their terminal state" \
    "rc=$progress_rc; $(cat "$WORK/progress-output" 2>/dev/null || true)"
fi

progress_rc=0
AGY_PROGRESS_INTERVAL_SECONDS=1 bash "$PROGRESS" --phase fixture-interrupt -- \
  bash -c 'sleep 30' >"$WORK/progress-output" 2>&1 &
progress_pid=$!
sleep 1
kill -TERM "$progress_pid"
wait "$progress_pid" || progress_rc=$?
if [ "$progress_rc" -eq 143 ] &&
  grep -Eq 'phase=fixture-interrupt state=interrupted .* exit_code=143$' \
    "$WORK/progress-output"; then
  pass "progress runner reports interruption and preserves the signal exit code"
else
  fail "progress runner reports interruption and preserves the signal exit code" \
    "rc=$progress_rc; $(cat "$WORK/progress-output" 2>/dev/null || true)"
fi

setup_repo
report="$WORK/report.json"
if run_review "$WORK/bin:$PATH" env GATEWAY_TOKEN=fixture-secret GITHUB_TOKEN=fixture-secret \
  FAKE_AGY_BUNDLE_CAPTURE="$WORK/review-bundle" AGY_REVIEW_REPORT_FILE="$report" &&
  [ "$(cat "$WORK/count")" -eq 2 ] &&
  [ "$(grep -Rl -- '--sandbox' "$WORK/calls" | wc -l)" -eq 2 ] &&
  grep -q 'dedicated semantic PII audit' "$WORK/calls/1.args" &&
  grep -q 'second independent Antigravity verifier' "$WORK/calls/2.args" &&
  ! grep -REq '=(fixture-secret|[^[:space:]]+)' "$WORK/calls"/*.credentials &&
  grep -q '^commit ' "$WORK/review-bundle" &&
  grep -q '^+change$' "$WORK/review-bundle" &&
  jq -e '.attempt_metadata == [
    {phase:"reviewer",count:1,class:"success",exit_status:0,elapsed_seconds:0},
    {phase:"verifier",count:1,class:"success",exit_status:0,elapsed_seconds:0}
  ]' "$report" >/dev/null &&
  grep -q 'gate passed' "$WORK/output"; then
  pass "reviewer and verifier succeed first try with isolated prompts and no inherited credentials"
else
  fail "clean branch receives two independent Antigravity passes" "$(cat "$WORK/output")"
fi

duplicate_result="$valid_result
$valid_result"
for entry in \
  'malformed JSON|not-json' \
  'missing result|{"event":"step_update"}' \
  "duplicate result|$duplicate_result" \
  'missing structured output|{"event":"result","result":{"status":"SUCCESS"}}' \
  'schema-invalid output|{"event":"result","result":{"status":"SUCCESS","structured_output":{"verdict":"pass","summary":"clean","findings":[],"next_steps":[]}}}'; do
  label=${entry%%|*}
  payload=${entry#*|}
  setup_repo
  queue_scenario 1 "$payload"
  report="$WORK/report.json"
  if run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" &&
    [ "$(cat "$WORK/count")" -eq 3 ] && [ "$(cat "$WORK/sleeps")" = 5 ] &&
    jq -e '.["attempt_metadata"][0].class == "invalid-structured-output" and
      .attempt_metadata[1].class == "success" and .attempt_metadata[2].phase == "verifier"' "$report" >/dev/null; then
    pass "$label recovers on the next reviewer attempt"
  else
    fail "$label recovery" "$(cat "$WORK/output")"
  fi
done

for entry in \
  'timeout stdout|request timed out||124' \
  'network stderr||network connection reset|19' \
  'rate-limit stdout|HTTP 429 rate limit exceeded||19' \
  'service-unavailable stderr||service unavailable temporarily|19'; do
  label=${entry%%|*}
  rest=${entry#*|}
  stdout=${rest%%|*}
  rest=${rest#*|}
  stderr=${rest%%|*}
  status=${rest##*|}
  setup_repo
  queue_scenario 1 "$stdout" "$stderr" "$status"
  report="$WORK/report.json"
  if run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" &&
    [ "$(cat "$WORK/count")" -eq 3 ] && [ "$(cat "$WORK/sleeps")" = 5 ] &&
    jq -e '.attempt_metadata[0].class == "transient-cli-failure" and .attempt_metadata[1].class == "success"' "$report" >/dev/null; then
    pass "$label is independently classified and recovered"
  else
    fail "$label recovery" "$(cat "$WORK/output")"
  fi
done

setup_repo
queue_async_stderr_scenario 1 "" 'network connection reset after command exit' 19
report="$WORK/report.json"
if run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" &&
  [ "$(cat "$WORK/count")" -eq 3 ] && [ "$(cat "$WORK/sleeps")" = 5 ] &&
  jq -e '.attempt_metadata[0].class == "transient-cli-failure" and .attempt_metadata[1].class == "success"' "$report" >/dev/null; then
  pass "delayed stderr is fully captured before retry classification"
else
  fail "delayed stderr synchronization" "$(cat "$WORK/output")"
fi

setup_repo
for attempt in 1 2 3; do
  queue_scenario "$attempt" 'timeout token=TOPSECRET' 'service unavailable password=HUSH' 19
done
report="$WORK/report.json" diagnostics="$WORK/diagnostics"
if run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" AGY_REVIEW_DIAGNOSTIC_DIR="$diagnostics"; then
  fail "three-attempt exhaustion" "review returned success"
elif [ "$(cat "$WORK/count")" -eq 3 ] && [ "$(cat "$WORK/sleeps")" = $'5\n15' ] &&
  jq -e '.reviewer.findings[0].severity == "critical" and
    ([.attempt_metadata[] | select(.phase == "reviewer" and .class == "transient-cli-failure")] | length == 3)' "$report" >/dev/null &&
  grep -Rqs '\[REDACTED\]' "$diagnostics" &&
  ! grep -REq 'TOPSECRET|HUSH' "$report" "$diagnostics" &&
  [ "$(find "$diagnostics" -type f -size +4096c | wc -l)" -eq 0 ]; then
  pass "exhaustion records exact 5s/15s backoff and only bounded redacted diagnostics"
else
  fail "three-attempt exhaustion metadata/redaction" "$(cat "$WORK/output")"
fi

for entry in 'authentication failed' 'invalid configuration' 'bad input'; do
  setup_repo
  queue_scenario 1 "" "$entry token=ONE_SHOT" 19
  report="$WORK/report.json"
  if ! run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" &&
    [ "$(cat "$WORK/count")" -eq 1 ] && [ ! -e "$WORK/sleeps" ] &&
    jq -e '.attempt_metadata == [{phase:"reviewer",count:1,class:"deterministic-cli-failure",exit_status:19,elapsed_seconds:0}]' "$report" >/dev/null; then
    pass "$entry terminates after one attempt"
  else
    fail "$entry retry policy" "$(cat "$WORK/output")"
  fi
done

for phase in reviewer verifier; do
  setup_repo
  [ "$phase" = reviewer ] && queue_scenario 1 "$high_result"
  [ "$phase" = verifier ] && queue_scenario 2 "$critical_result"
  report="$WORK/report.json"
  if ! run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" &&
    [ "$(cat "$WORK/count")" -eq 2 ] && [ ! -e "$WORK/sleeps" ] &&
    jq -e --arg phase "$phase" '.[$phase].findings[0].severity | . == "high" or . == "critical"' "$report" >/dev/null; then
    pass "valid $phase blocking finding blocks without retry"
  else
    fail "$phase blocking finding" "$(cat "$WORK/output")"
  fi
done

setup_repo
for attempt in 2 3 4; do queue_scenario "$attempt" "" 'network timeout token=VERIFIER_SECRET' 19; done
report="$WORK/report.json" diagnostics="$WORK/diagnostics"
if ! run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" AGY_REVIEW_DIAGNOSTIC_DIR="$diagnostics" &&
  [ "$(cat "$WORK/count")" -eq 4 ] && [ "$(cat "$WORK/sleeps")" = $'5\n15' ] &&
  jq -e '.reviewer.verdict == "approve" and .verifier.findings[0].severity == "critical" and
    ([.attempt_metadata[] | select(.phase == "verifier")] | length == 3)' "$report" >/dev/null &&
  ! grep -REq 'VERIFIER_SECRET' "$report" "$diagnostics"; then
  pass "verifier exhaustion preserves reviewer report and synthesizes only verifier failure"
else
  fail "verifier exhaustion preservation" "$(cat "$WORK/output")"
fi

setup_repo
printf '1000\n3700\n' >"$WORK/date-values"
report="$WORK/report.json"
if ! run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" && [ ! -e "$WORK/count" ] &&
  jq -e '.attempt_metadata[0].class == "budget-exhausted" and .reviewer.findings[0].severity == "critical"' "$report" >/dev/null; then
  pass "exhausted shared budget blocks without calling agy"
else
  fail "zero shared budget" "$(cat "$WORK/output")"
fi

setup_repo
queue_scenario 1 'request timed out' '' 124
printf '1000\n1000\n1000\n1000\n2260\n' >"$WORK/date-values"
report="$WORK/report.json"
if ! run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" &&
  [ "$(cat "$WORK/count")" -eq 1 ] && [ ! -e "$WORK/sleeps" ] &&
  jq -e '.attempt_metadata[-1].class == "budget-exhausted" and .attempt_metadata[-1].phase == "reviewer"' "$report" >/dev/null; then
  pass "reviewer retry is refused when verifier reserve would be consumed"
else
  fail "reviewer reserved budget" "$(cat "$WORK/output")"
fi

setup_repo
queue_scenario 2 '' 'network timeout' 19
printf '1000\n1000\n1000\n1000\n1000\n1000\n1000\n2976\n' >"$WORK/date-values"
report="$WORK/report.json"
if ! run_review "$WORK/bin:$PATH" env AGY_REVIEW_REPORT_FILE="$report" &&
  [ "$(cat "$WORK/count")" -eq 2 ] && [ ! -e "$WORK/sleeps" ] &&
  jq -e '.reviewer.verdict == "approve" and .attempt_metadata[-1].class == "budget-exhausted" and
    .attempt_metadata[-1].phase == "verifier"' "$report" >/dev/null; then
  pass "verifier retry is refused when its own remaining budget is insufficient"
else
  fail "verifier remaining budget" "$(cat "$WORK/output")"
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
    FAKE_AGY_QUEUE="$WORK/scenarios" FAKE_CLOCK="$WORK/clock" FAKE_DATE_COUNT="$WORK/date-count" \
    FAKE_DATE_VALUES="$WORK/date-values" FAKE_SLEEP_RECEIPTS="$WORK/sleeps" \
    AGY_REVIEW_ACTIVE=1 bash scripts/agy-pre-push-review.sh
) >"$WORK/output" 2>&1 || rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$WORK/count" ] && grep -q 'nested.*refused' "$WORK/output"; then
  pass "recursive review is rejected before another model call"
else
  fail "recursive review is rejected" "rc=$rc; $(cat "$WORK/output")"
fi

printf '\nResults: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
