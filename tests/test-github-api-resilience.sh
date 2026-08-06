#!/usr/bin/env bash
# Hermetic contract tests for GitHub API retry/defer behavior and Antigravity wiring.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
module="$repo_root/scripts/github-api-resilience.cjs"

node - "$module" <<'NODE'
const assert = require('node:assert/strict');
const modulePath = process.argv[2];
(async () => {
const {
  GitHubRetryDeferredError,
  classifyGitHubError,
  computeWaitSeconds,
  formatRetryProgress,
  readPrimaryRateLimit,
  requestGitHubApi,
  retryGitHub,
} = require(modulePath);

const error = (message, status, headers = {}) => Object.assign(new Error(message), {
  status,
  response: {status, headers},
});

const primary = classifyGitHubError(error('API rate limit exceeded', 403, {
  'x-ratelimit-remaining': '0',
  'x-ratelimit-reset': '1120',
}));
assert.equal(primary.kind, 'primary');
assert.equal(primary.retryable, true);
assert.equal(primary.resetAtSeconds, 1120);
assert.equal(computeWaitSeconds(primary, {
  attempt: 1,
  nowSeconds: 1000,
  jitterSeconds: 0,
  random: () => 0,
}), 125);

const retryAfter = classifyGitHubError(error('secondary rate limit', 403, {
  'retry-after': '90',
  'x-ratelimit-remaining': '4999',
}));
assert.equal(retryAfter.kind, 'secondary');
assert.equal(retryAfter.retryAfterSeconds, 90);
assert.equal(computeWaitSeconds(retryAfter, {
  attempt: 1,
  nowSeconds: 1000,
  jitterSeconds: 0,
  random: () => 0,
}), 90);

const contentLimit = classifyGitHubError(error(
  'temporarily blocked from content creation; was submitted too quickly',
  403,
));
assert.equal(contentLimit.kind, 'secondary');
assert.equal(computeWaitSeconds(contentLimit, {
  attempt: 3,
  nowSeconds: 1000,
  jitterSeconds: 0,
  random: () => 0,
}), 240);
assert.equal(computeWaitSeconds(contentLimit, {
  attempt: 8,
  nowSeconds: 1000,
  jitterSeconds: 0,
  maxBackoffSeconds: 600,
  random: () => 0,
}), 600);

assert.deepEqual(classifyGitHubError(error('Service unavailable', 503)).kind, 'transient');
assert.equal(classifyGitHubError(error('Bad credentials', 401)).retryable, false);
assert.equal(classifyGitHubError(error('Validation failed', 422)).retryable, false);

let rateCalls = 0;
const rate = await readPrimaryRateLimit({
  request: async (route) => {
    rateCalls += 1;
    assert.equal(route, 'GET /rate_limit');
    return {data: {resources: {core: {limit: 5000, remaining: 0, reset: 1120}}}};
  },
});
assert.deepEqual(rate, {limit: 5000, remaining: 0, resetAtSeconds: 1120, resource: 'core'});
assert.equal(rateCalls, 1);

const sleeps = [];
const progress = [];
let calls = 0;
let primaryLookups = 0;
const result = await retryGitHub(async () => {
  calls += 1;
  if (calls < 3) throw error('secondary rate limit', 403);
  return 'ok';
}, {
  operationName: 'publish exact-head receipt',
  maxAttempts: 4,
  totalWaitBudgetSeconds: 600,
  jitterSeconds: 0,
  nowSeconds: () => 1000 + sleeps.reduce((sum, value) => sum + value, 0),
  random: () => 0,
  sleepSeconds: async (seconds) => sleeps.push(seconds),
  readPrimaryRateLimit: async () => {
    primaryLookups += 1;
    return rate;
  },
  onProgress: (event) => progress.push(event),
});
assert.equal(result, 'ok');
assert.deepEqual(sleeps, [60, 120]);
assert.equal(primaryLookups, 0, 'secondary cooldown must not poll /rate_limit');
assert.equal(progress.length, 2);
assert.match(formatRetryProgress(progress[0]), /^\[WAIT\]/);
assert.match(formatRetryProgress(progress[0]), /publish exact-head receipt/);
assert.match(formatRetryProgress(progress[0]), /attempt 1\/4/);
assert.match(formatRetryProgress(progress[0]), /next attempt 1970-01-01T00:17:40.000Z/);

let primaryAttempts = 0;
const primarySleeps = [];
await retryGitHub(async () => {
  primaryAttempts += 1;
  if (primaryAttempts === 1) {
    throw error('API rate limit exceeded', 403, {'x-ratelimit-remaining': '0'});
  }
  return 'primary recovered';
}, {
  operationName: 'read fleet state',
  maxAttempts: 2,
  totalWaitBudgetSeconds: 200,
  jitterSeconds: 0,
  nowSeconds: () => 1000,
  random: () => 0,
  sleepSeconds: async (seconds) => primarySleeps.push(seconds),
  readPrimaryRateLimit: async () => ({
    limit: 5000,
    remaining: 0,
    resetAtSeconds: 1120,
    resource: 'core',
  }),
  onProgress: () => {},
});
assert.deepEqual(primarySleeps, [125]);

let deferred;
try {
  await retryGitHub(async () => {
    throw error('secondary rate limit', 403, {'retry-after': '120'});
  }, {
    operationName: 'create exact-head comment',
    maxAttempts: 3,
    totalWaitBudgetSeconds: 60,
    jitterSeconds: 0,
    nowSeconds: () => 1000,
    random: () => 0,
    sleepSeconds: async () => assert.fail('must not sleep past the wait budget'),
    onProgress: () => {},
  });
} catch (caught) {
  deferred = caught;
}
assert.ok(deferred instanceof GitHubRetryDeferredError);
assert.equal(deferred.code, 84);
assert.equal(deferred.kind, 'secondary');
assert.equal(deferred.waitSeconds, 120);

let fatalCalls = 0;
await assert.rejects(
  retryGitHub(async () => {
    fatalCalls += 1;
    throw error('Validation failed', 422);
  }, {
    operationName: 'invalid mutation',
    sleepSeconds: async () => assert.fail('fatal errors must not sleep'),
    onProgress: () => {},
  }),
  /Validation failed/,
);
assert.equal(fatalCalls, 1);

const response = (status, body, headers = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: {
    get: (name) => Object.entries(headers).find(
      ([key]) => key.toLowerCase() === name.toLowerCase(),
    )?.[1] ?? null,
  },
  text: async () => JSON.stringify(body),
});
const requestSleeps = [];
const requestUrls = [];
const requestResult = await requestGitHubApi('repos/f5-sales-demo/example', {
  token: 'synthetic-token',
  jitterSeconds: 0,
  sleepSeconds: async (seconds) => requestSleeps.push(seconds),
  onProgress: () => {},
  fetch: async (url, options) => {
    requestUrls.push(url);
    assert.equal(options.headers.authorization, 'Bearer synthetic-token');
    if (requestUrls.length === 1) {
      return response(403, {message: 'secondary rate limit'}, {'Retry-After': '7'});
    }
    return response(200, {repository: 'f5-sales-demo/example'});
  },
});
assert.deepEqual(requestSleeps, [7]);
assert.deepEqual(requestResult, {repository: 'f5-sales-demo/example'});
assert.equal(requestUrls.some((url) => url.endsWith('/rate_limit')), false);

const primaryUrls = [];
const primaryRequestSleeps = [];
let repositoryCalls = 0;
await requestGitHubApi('repos/f5-sales-demo/example', {
  token: 'synthetic-token',
  jitterSeconds: 0,
  nowSeconds: () => 1000,
  sleepSeconds: async (seconds) => primaryRequestSleeps.push(seconds),
  onProgress: () => {},
  fetch: async (url) => {
    primaryUrls.push(url);
    if (url.endsWith('/rate_limit')) {
      return response(200, {resources: {core: {limit: 5000, remaining: 0, reset: 1120}}});
    }
    repositoryCalls += 1;
    if (repositoryCalls === 1) return response(403, {message: 'API rate limit exceeded'});
    return response(200, {repository: 'f5-sales-demo/example'});
  },
});
assert.deepEqual(primaryRequestSleeps, [125]);
assert.equal(primaryUrls.filter((url) => url.endsWith('/rate_limit')).length, 1);

console.log('[OK] GitHub API retry classifications and wait contract');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
NODE

fail=0
check() {
  local label="$1"
  shift
  if "$@"; then
    printf '[OK] %s\n' "$label"
  else
    printf '[FAIL] %s\n' "$label" >&2
    fail=1
  fi
}

watcher="$repo_root/.github/workflows/antigravity-fleet-watcher.yml"
review="$repo_root/.github/workflows/antigravity-review.yml"
translation="$repo_root/.github/workflows/antigravity-translate.yml"
translation_caller="$repo_root/workflows/antigravity-translate.yml"

check 'unconfigured GitHub App credentials are absent' \
  bash -c "! grep -qE 'AUTOMATION_APP_ID|AUTOMATION_APP_PRIVATE_KEY|create-github-app-token' \
    '$watcher' '$translation' '$translation_caller'"
check 'fleet watcher uses the existing fleet token' \
  grep -qF 'secrets.REPO_SETTINGS_TOKEN' "$watcher"
check 'translation caller uses the existing fleet sync token' \
  grep -qF 'REPO_SYNC_TOKEN: ${{ secrets.REPO_SYNC_TOKEN }}' "$translation_caller"

for workflow in "$watcher" "$review" "$translation"; do
  check "$(basename "$workflow") loads the governed retry helper" \
    grep -qF 'github-api-resilience.cjs' "$workflow"
  check "$(basename "$workflow") uses bounded GitHub retry" \
    grep -qF 'retryGitHub' "$workflow"
done

check 'review receipts are exact-head markers' \
  grep -qE 'antigravity-pr-review:\$\{?[^}]*HEAD|antigravity-pr-review:\$\{report[.]receipt[.]head_sha\}' "$review"
check 'watcher redispatches failed or unpublished exact reviews' \
  grep -qF 'reviewNeedsRecovery' "$watcher"
check 'watcher redispatches failed exact translations' \
  grep -qF 'translationNeedsRecovery' "$watcher"
check 'watcher emits per-repository progress heartbeats' \
  grep -qE '\[PROGRESS\].*repository' "$watcher"
check 'Free-tier contract remains explicit' \
  grep -qF 'GitHub Free-compatible' "$watcher"
check 'operator guidance documents secondary cooldown without polling' \
  bash -c "grep -qF 'Secondary limits never poll during cooldown' '$repo_root/CONTRIBUTING.md' && \
    grep -qF 'Retry-After' '$repo_root/CONTRIBUTING.md'"
check 'managed-file sync avoids GraphQL content mutations' \
  bash -c "! grep -qE 'gh (issue create|issue close|pr create|pr close|pr merge)' \
    '$repo_root/.github/workflows/sync-managed-files.yml'"

check 'retry helper is managed fleet-wide' jq -e \
  '.managed_files.files | any(.src == "scripts/github-api-resilience.cjs" and .dest == "scripts/github-api-resilience.cjs")' \
  "$repo_root/.github/config/repo-settings.json"
check 'retry helper is governance-protected' jq -e \
  '.protected_files | index("scripts/github-api-resilience.cjs") != null' \
  "$repo_root/.claude/governance.json"

exit "$fail"
