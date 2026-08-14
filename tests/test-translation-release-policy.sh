#!/usr/bin/env bash
# Hermetic coverage for next-major-only translation release eligibility.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$REPO_ROOT/scripts/translation-release-policy.sh"
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
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

assert_decision() {
  local expected=$1 label=$2 head_ref=$3 tags=$4
  printf '%s\n' "$tags" >"$WORK/tags"
  local output
  if ! output=$(bash "$SCRIPT" --head-ref "$head_ref" --tags-file "$WORK/tags" 2>&1); then
    fail "$label" "$output"
    return
  fi
  if grep -qxF "eligible=$expected" <<<"$output"; then
    pass "$label"
  else
    fail "$label" "$output"
  fi
}

echo "Translation major-release policy tests"

assert_decision true "next stable major is eligible" \
  release/v20.0.0 $'v19.105.7\nv19.0.0\nv18.9.2'
assert_decision false "minor release is ineligible" \
  release/v20.1.0 $'v19.105.7\nv19.0.0'
assert_decision false "patch release is ineligible" \
  release/v20.0.1 $'v19.105.7\nv19.0.0'
assert_decision false "ordinary development branch is ineligible" \
  feature/1344-major-release-translations $'v19.105.7\nv19.0.0'
assert_decision false "existing major cannot be reconciled twice" \
  release/v20.0.0 $'v20.0.0\nv19.105.7'
assert_decision false "skipping a major is ineligible" \
  release/v21.0.0 $'v19.105.7\nv19.0.0'
assert_decision true "first stable major starts at v1" \
  release/v1.0.0 $'package/v9.0.0\nv1.0.0-rc.1\nrelease-2026.08'
assert_decision false "first stable major cannot start above v1" \
  release/v2.0.0 $'package/v1.0.0\nv1.0.0-rc.1'
assert_decision true "prerelease and namespaced tags do not alter root stable history" \
  release/v3.0.0 $'v2.9.0\nv3.0.0-rc.1\ngithub/v99.0.0'
assert_decision false "leading-zero major is rejected" \
  release/v03.0.0 $'v2.9.0'

WATCHER="$REPO_ROOT/.github/workflows/antigravity-fleet-watcher.yml"
WATCHER_COLLECTOR="$REPO_ROOT/scripts/collect-antigravity-fleet-state.sh"
CALLER="$REPO_ROOT/workflows/antigravity-translate.yml"
TRANSLATE="$REPO_ROOT/.github/workflows/antigravity-translate.yml"
AUDIT="$REPO_ROOT/.github/workflows/translation-audit.yml"

# The policy script and the decisions above are fleet-managed. The remaining
# assertions cover docs-control's canonical implementation, whose fleet watcher
# and reusable workflow are deliberately absent from downstream repositories.
if [ ! -f "$WATCHER" ] && [ ! -f "$CALLER" ]; then
  printf '  SKIP: docs-control-only translation workflow assertions are not applicable\n'
  printf '\nResults: %d passed, %d failed\n' "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
  exit
fi

for subject in "$WATCHER" "$CALLER" "$TRANSLATE" "$AUDIT"; do
  if [ ! -f "$subject" ]; then
    fail "docs-control translation workflow subjects are complete" \
      "missing ${subject#"$REPO_ROOT"/}"
  fi
done
if [ "$FAIL" -ne 0 ]; then
  printf '\nResults: %d passed, %d failed\n' "$PASS" "$FAIL"
  exit 1
fi

AUDIT_BODY=$(awk '
  /^      - name: Audit translation freshness$/ {step=1}
  step && /^        run: \|$/ {capture=1; next}
  capture && /^          / {sub(/^          /, ""); print; next}
  capture {exit}
' "$AUDIT")

assert_audit_without_scripts() {
  local expected=$1 label=$2 head_ref=$3
  local scenario="$WORK/audit-$PASS-$FAIL"
  mkdir -p "$scenario/consumer" "$scenario/temp"
  git -C "$scenario/consumer" init -q

  local output rc
  set +e
  output=$(cd "$scenario/consumer" &&
    RUNNER_TEMP="$scenario/temp" HEAD_REF="$head_ref" bash -c "$AUDIT_BODY" 2>&1)
  rc=$?
  set -e

  if [ "$expected" = success ] && [ "$rc" -eq 0 ] &&
    grep -qF 'not applicable outside an exact major-release branch' <<<"$output"; then
    pass "$label"
  elif [ "$expected" = failure ] && [ "$rc" -ne 0 ] &&
    grep -qF 'scripts/translation-release-policy.sh' <<<"$output"; then
    pass "$label"
  else
    fail "$label" "exit=$rc output=$output"
  fi
}

assert_audit_without_scripts success \
  "exact-caller bootstrap is not applicable before policy scripts arrive" \
  sync/exact-caller-deadbeef
assert_audit_without_scripts success \
  "ordinary development is not applicable before policy scripts arrive" \
  feature/1358-bootstrap-safe-translation-audit
assert_audit_without_scripts success \
  "minor releases are not applicable before policy scripts arrive" \
  release/v20.1.0
assert_audit_without_scripts success \
  "patch releases are not applicable before policy scripts arrive" \
  release/v20.0.1
assert_audit_without_scripts success \
  "prefixed major-like branches are not applicable before policy scripts arrive" \
  preview/release/v20.0.0
assert_audit_without_scripts success \
  "leading-zero major branches are not applicable before policy scripts arrive" \
  release/v020.0.0
assert_audit_without_scripts failure \
  "exact major candidates fail closed when policy scripts are absent" \
  release/v20.0.0

assert_exact_audit_route() {
  local eligible=$1 expected_calls=$2 label=$3
  local scenario="$WORK/exact-$eligible"
  mkdir -p "$scenario/consumer" "$scenario/governance/scripts" "$scenario/temp"
  git -C "$scenario/consumer" init -q
  cat >"$scenario/governance/scripts/translation-release-policy.sh" <<'EOF'
#!/usr/bin/env bash
printf 'policy\n' >>"$AUDIT_CALLS"
printf 'eligible=%s\n' "$FAKE_ELIGIBLE"
EOF
  cat >"$scenario/governance/scripts/validate-translations.sh" <<'EOF'
#!/usr/bin/env bash
printf 'validator:%s\n' "$*" >>"$AUDIT_CALLS"
EOF

  local output rc
  set +e
  output=$(cd "$scenario/consumer" &&
    AUDIT_CALLS="$scenario/calls" FAKE_ELIGIBLE="$eligible" \
      RUNNER_TEMP="$scenario/temp" HEAD_REF=release/v20.0.0 \
      bash -c "$AUDIT_BODY" 2>&1)
  rc=$?
  set -e

  if [ "$rc" -eq 0 ] && [ "$(cat "$scenario/calls")" = "$expected_calls" ]; then
    pass "$label"
  else
    fail "$label" "exit=$rc calls=$(cat "$scenario/calls" 2>/dev/null || true) output=$output"
  fi
}

assert_exact_audit_route true $'policy\nvalidator:--all' \
  "policy-approved exact major candidates run the full-corpus validator"
assert_exact_audit_route false 'policy' \
  "policy-rejected exact major candidates do not run the validator"

if grep -qF 'scripts/translation-release-policy.sh' "$WATCHER_COLLECTOR" &&
  grep -qF -- '--argjson reconcile_all true' "$WATCHER_COLLECTOR"; then
  pass "fleet watcher routes only policy-approved full reconciliation"
else
  fail "fleet watcher routes only policy-approved full reconciliation" \
    "release policy or reconciliation dispatch is absent"
fi

if grep -qF 'reconcile_all:' "$CALLER" && grep -qF 'reconcile_all:' "$TRANSLATE" &&
  grep -qF 'RECONCILE_ALL:' "$TRANSLATE"; then
  pass "caller and reusable workflow bind reconciliation mode"
else
  fail "caller and reusable workflow bind reconciliation mode" \
    "reconcile_all is not bound end to end"
fi

if grep -qF 'working-directory: consumer' "$AUDIT" &&
  grep -qF 'bash ../governance/scripts/translation-release-policy.sh' "$AUDIT" &&
  grep -qF 'bash ../governance/scripts/validate-translations.sh --all' "$AUDIT"; then
  pass "freshness audit is major-release-only and validates the full consumer corpus"
else
  fail "freshness audit is major-release-only and validates the full consumer corpus" \
    "trusted audit policy or full validation route is absent"
fi

if grep -qF 'JOB_CONTEXT: ${{ toJSON(job) }}' "$AUDIT" &&
  grep -qF "repository=\$(jq -r '.workflow_repository // \"\"'" "$AUDIT" &&
  grep -qF "sha=\$(jq -r '.workflow_sha // \"\"'" "$AUDIT" &&
  grep -qF 'repository: ${{ steps.governance.outputs.repository }}' "$AUDIT" &&
  grep -qF 'ref: ${{ steps.governance.outputs.sha }}' "$AUDIT" &&
  grep -qF 'test "$GOVERNANCE_REPOSITORY" = "f5-sales-demo/docs-control"' "$AUDIT" &&
  grep -qF 'test "$(git -C governance rev-parse HEAD)" = "$GOVERNANCE_SHA"' "$AUDIT"; then
  pass "freshness audit binds tooling to its exact reusable-workflow receipt"
else
  fail "freshness audit binds tooling to its exact reusable-workflow receipt" \
    "trusted workflow repository or immutable receipt verification is absent"
fi

if [ "$(grep -cF 'persist-credentials: false' "$AUDIT")" -eq 2 ] &&
  grep -qF 'path: consumer' "$AUDIT" && grep -qF 'path: governance' "$AUDIT"; then
  pass "consumer and governance checkouts are isolated and credential-free"
else
  fail "consumer and governance checkouts are isolated and credential-free" \
    "checkout isolation or credential suppression is incomplete"
fi

if grep -Eq '(^|[[:space:]])bash scripts/(translation-release-policy|validate-translations)\.sh' "$AUDIT"; then
  fail "freshness audit never executes pull-request-controlled policy scripts" \
    "audit invokes a translation policy script from the consumer checkout"
else
  pass "freshness audit never executes pull-request-controlled policy scripts"
fi

printf '\nResults: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
