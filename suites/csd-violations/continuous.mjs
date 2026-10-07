import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, readFile, rename, rm, statfs } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HEADER_SCENARIO_SELECTORS, SCENARIO_NAMES, SUITE_MANIFEST } from './scenarios.mjs';

const FROZEN_SCENARIOS = Object.freeze([
  'login-credential-skimmer',
  'registration-harvester',
  'payment-overlay-card-skimmer',
  'obfuscated-loader',
  'multi-cdn-injection',
  'tag-manager-hijack',
  'multi-channel-exfiltration',
  'high-volume-domain-exfiltration',
  'form-overlay',
  'keylogger-simulation',
  'maximum-detection',
  'header-omit-x-content-type-options',
  'header-omit-x-frame-options',
  'header-omit-cache-control',
]);
const HEADER_SCENARIOS = Object.keys(HEADER_SCENARIO_SELECTORS);
const epoch = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 8640000000000000;
const exactKeys = (value, keys) =>
  value &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

const SOURCE = '/opt/traffic-generator/source';
const ENV_FILE = '/etc/traffic-generator/runtime.env';
const RUN_SCRIPT = `${SOURCE}/suites/csd-violations/run.sh`;
const STATE_DIRECTORY = '/opt/traffic-generator/runtime/continuous';
const RESULTS_ROOT = '/opt/traffic-generator/runtime/results';
const TARGET = 'https://client-side-defense.f5-sales-demo.com';
const GiB = 1024 ** 3;
export const DEFAULT_POLICY = Object.freeze({
  scenarioMs: 900000,
  finalizationMs: 120000,
  cleanupMs: 30000,
  maxAttempts: 3,
  backoffMs: Object.freeze([30000, 60000, 120000]),
  maxBackoffMs: 300000,
  maxPendingUploads: 32,
  uploadAttempts: 3,
  uploadMs: 120000,
  maxDetailBytes: 5 * GiB,
  retentionMs: 7 * 86400000,
  minFreeBytes: GiB,
  maxPendingBytes: 2 * GiB,
  maxRunBytes: 256 * 1024 ** 2,
  maxOutputBytes: 65536,
  maxStateBytes: 65536,
  maxFiles: 100000,
  monitorMs: 1000,
});
const CATEGORIES = new Set([
  'ok',
  'busy',
  'interrupted',
  'timeout',
  'scenario_failure',
  'upload_transient',
  'target_transient',
  'fatal_config',
  'fatal_provenance',
  'fatal_target',
  'fatal_integrity',
  'fatal_auth',
  'disk_blocked',
]);
const STATES = new Set(['idle', 'running', 'backoff', 'busy', 'blocked', 'interrupted']);
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,127}$/;
const COUNTERS = [
  'cursor',
  'completedCycles',
  'attemptedRuns',
  'browserPassedRuns',
  'committedRuns',
  'failedRuns',
  'timeoutRuns',
  'interruptedRuns',
  'busyCount',
  'retryAttempt',
];
const STATE_FIELDS = [
  'schemaVersion',
  'sourceCommit',
  'manifestDigest',
  'status',
  ...COUNTERS,
  'currentScenario',
  'currentRunId',
  'nextAttemptAt',
  'lastStartedAt',
  'lastCompletedAt',
  'heartbeatAt',
  'lastOutcome',
  'pendingUploads',
  'headerCadence',
];
const RUNTIME_KEYS = new Set([
  'TARGET_URL',
  'CONTINUOUS_ENABLED',
  'SOURCE_COMMIT',
  'DEPLOYMENT_MANIFEST_SHA256',
  'DEPLOYMENT_MANIFEST_VERSION',
  'SOURCE_REPOSITORY_URL',
  'CSD_AWS_RUNTIME',
  'AWS_REGION',
  'AMI_ID',
  'EVIDENCE_BUCKET',
  'AWS_CLI_BIN',
  'AWS_CLI_VERSION',
  'NODE_PATH',
  'CHROME_BIN',
  'DISPLAY',
  'LOG_GROUP_NAME',
  'CHROME_VERSION',
  'NODE_VERSION',
  'PLAYWRIGHT_VERSION',
]);
const fatal = (category) => category.startsWith('fatal_') || category === 'disk_blocked';
function failure(category) {
  const error = new Error(category);
  error.category = category;
  return error;
}
const classify = (error, fallback = 'fatal_integrity') => (CATEGORIES.has(error?.category) ? error.category : fallback);

function hasControlCharacters(value) {
  return Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 31 || code === 127;
  });
}

export function validateConfig(input) {
  let config;
  if (typeof input === 'string') {
    config = {};
    for (const line of input.split(/\r?\n/)) {
      if (line === '' || /^#[^\r\n]*$/.test(line)) continue;
      const match = /^([A-Z][A-Z0-9_]*)=([^\s"'`$\\;<>|&()]*)$/.exec(line);
      if (!match || hasControlCharacters(match[2]) || Object.hasOwn(config, match[1])) throw failure('fatal_config');
      config[match[1]] = match[2];
    }
  } else {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw failure('fatal_config');
    config = { ...input };
    for (const [key, value] of Object.entries(config)) {
      if (
        !/^[A-Z][A-Z0-9_]*$/.test(key) ||
        typeof value !== 'string' ||
        hasControlCharacters(value) ||
        /[\s"'`$\\;<>|&()]/.test(value)
      )
        throw failure('fatal_config');
    }
  }
  if (Object.keys(config).some((key) => !RUNTIME_KEYS.has(key))) throw failure('fatal_config');
  if (config.TARGET_URL !== TARGET) throw failure('fatal_target');
  const rules = {
    CONTINUOUS_ENABLED: /^[01]$/,
    SOURCE_COMMIT: /^[a-f0-9]{40}$/,
    DEPLOYMENT_MANIFEST_SHA256: /^[a-f0-9]{64}$/,
    DEPLOYMENT_MANIFEST_VERSION: /^1\.1\.0$/,
    SOURCE_REPOSITORY_URL: /^https:\/\/github\.com\/f5-sales-demo\/traffic-generator\.git$/,
    CSD_AWS_RUNTIME: /^1$/,
    AWS_REGION: /^[a-z]{2}(?:-[a-z]+)+-\d$/,
    AMI_ID: /^ami-[a-f0-9]{8,17}$/,
    EVIDENCE_BUCKET: /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/,
    AWS_CLI_BIN: /^\/usr\/local\/bin\/aws$/,
    AWS_CLI_VERSION: /^2\.\d+\.\d+$/,
    NODE_PATH: /^\/opt\/traffic-generator\/node_modules$/,
    CHROME_BIN: /^\/opt\/chrome\/chrome$/,
    DISPLAY: /^:99$/,
  };
  for (const [key, regex] of Object.entries(rules)) if (!regex.test(config[key] ?? '')) throw failure('fatal_config');
  if (
    SUITE_MANIFEST.schemaVersion !== '1.1.0' ||
    SCENARIO_NAMES.length !== FROZEN_SCENARIOS.length ||
    SCENARIO_NAMES.some((name, index) => name !== FROZEN_SCENARIOS[index]) ||
    SUITE_MANIFEST.scenarios.some(({ name }, index) => name !== FROZEN_SCENARIOS[index]) ||
    SUITE_MANIFEST.scenarios.length !== FROZEN_SCENARIOS.length
  )
    throw failure('fatal_provenance');
  return Object.freeze(config);
}
function freshState(config, now) {
  return {
    schemaVersion: 2,
    sourceCommit: config?.SOURCE_COMMIT ?? null,
    manifestDigest: config?.DEPLOYMENT_MANIFEST_SHA256 ?? null,
    status: 'idle',
    cursor: 0,
    completedCycles: 0,
    attemptedRuns: 0,
    browserPassedRuns: 0,
    committedRuns: 0,
    failedRuns: 0,
    timeoutRuns: 0,
    interruptedRuns: 0,
    busyCount: 0,
    currentScenario: null,
    currentRunId: null,
    retryAttempt: 0,
    nextAttemptAt: 0,
    lastStartedAt: null,
    lastCompletedAt: null,
    heartbeatAt: now,
    lastOutcome: null,
    pendingUploads: [],
    headerCadence: Object.fromEntries(
      HEADER_SCENARIOS.map((name) => [
        name,
        {
          lastPairStartedAt: null,
          lastPairCompletedAt: null,
          lastPairOutcome: null,
        },
      ]),
    ),
  };
}
function checkedState(input) {
  if (!exactKeys(input, STATE_FIELDS) || input.schemaVersion !== 2 || !STATES.has(input.status))
    throw failure('fatal_integrity');
  if (!exactKeys(input.headerCadence, HEADER_SCENARIOS)) throw failure('fatal_integrity');
  for (const entry of Object.values(input.headerCadence)) {
    if (
      !exactKeys(entry, ['lastPairStartedAt', 'lastPairCompletedAt', 'lastPairOutcome']) ||
      (entry.lastPairStartedAt === null
        ? entry.lastPairCompletedAt !== null || entry.lastPairOutcome !== null
        : !epoch(entry.lastPairStartedAt) ||
          !['passed', 'failed'].includes(entry.lastPairOutcome) ||
          (entry.lastPairCompletedAt === null
            ? entry.lastPairOutcome !== 'failed'
            : !epoch(entry.lastPairCompletedAt) || entry.lastPairCompletedAt < entry.lastPairStartedAt))
    )
      throw failure('fatal_integrity');
  }
  for (const key of COUNTERS) if (!Number.isSafeInteger(input[key]) || input[key] < 0) throw failure('fatal_integrity');
  if (input.cursor >= SCENARIO_NAMES.length || input.retryAttempt > DEFAULT_POLICY.maxAttempts)
    throw failure('fatal_integrity');
  if (input.sourceCommit !== null && !/^[a-f0-9]{40}$/.test(input.sourceCommit)) throw failure('fatal_integrity');
  if (input.manifestDigest !== null && !/^[a-f0-9]{64}$/.test(input.manifestDigest)) throw failure('fatal_integrity');
  if (input.currentRunId !== null && !RUN_ID.test(input.currentRunId)) throw failure('fatal_integrity');
  if (input.currentScenario !== null && !SCENARIO_NAMES.includes(input.currentScenario))
    throw failure('fatal_integrity');
  if (input.lastOutcome !== null && !CATEGORIES.has(input.lastOutcome)) throw failure('fatal_integrity');
  for (const key of ['nextAttemptAt', 'heartbeatAt', 'lastStartedAt', 'lastCompletedAt']) {
    if (input[key] !== null && (!Number.isSafeInteger(input[key]) || input[key] < 0)) throw failure('fatal_integrity');
  }
  if (!Array.isArray(input.pendingUploads) || input.pendingUploads.length > DEFAULT_POLICY.maxPendingUploads)
    throw failure('fatal_integrity');
  const ids = new Set();
  const pendingUploads = input.pendingUploads.map((entry) => {
    if (
      !entry ||
      !RUN_ID.test(entry.runId) ||
      !SCENARIO_NAMES.includes(entry.scenario) ||
      !Number.isSafeInteger(entry.attempts) ||
      entry.attempts < 0 ||
      entry.attempts > DEFAULT_POLICY.uploadAttempts ||
      !Number.isSafeInteger(entry.nextAttemptAt) ||
      entry.nextAttemptAt < 0 ||
      typeof entry.exhausted !== 'boolean' ||
      entry.exhausted !== entry.attempts >= DEFAULT_POLICY.uploadAttempts ||
      ids.has(entry.runId)
    )
      throw failure('fatal_integrity');
    ids.add(entry.runId);
    const headerPair = HEADER_SCENARIO_SELECTORS[entry.scenario]
      ? checkedHeaderPair(entry.headerPair, entry.scenario)
      : null;
    return {
      runId: entry.runId,
      scenario: entry.scenario,
      attempts: entry.attempts,
      nextAttemptAt: entry.nextAttemptAt,
      exhausted: entry.exhausted,
      ...(headerPair ? { headerPair } : {}),
    };
  });
  const state = Object.fromEntries(STATE_FIELDS.map((key) => [key, input[key]]));
  state.pendingUploads = pendingUploads;
  return state;
}
function checkedHeaderPair(pair, scenario) {
  const selector = HEADER_SCENARIO_SELECTORS[scenario];
  if (!selector) {
    if (pair !== null) throw failure('fatal_integrity');
    return null;
  }
  if (
    !exactKeys(pair, ['selector', 'scope', 'pairStartedAt', 'pairCompletedAt', 'result']) ||
    pair.selector !== selector ||
    !['document', 'same-origin'].includes(pair.scope) ||
    !epoch(pair.pairStartedAt) ||
    !['passed', 'failed'].includes(pair.result) ||
    (pair.pairCompletedAt === null
      ? pair.result !== 'failed'
      : !epoch(pair.pairCompletedAt) || pair.pairCompletedAt < pair.pairStartedAt)
  )
    throw failure('fatal_integrity');
  return { ...pair };
}
function browserPassed(result) {
  return (
    result.browserExit === 0 && (!HEADER_SCENARIO_SELECTORS[result.scenario] || result.headerPair?.result === 'passed')
  );
}
function categoryOf(result) {
  const category = result?.failureCategory || result?.outcome;
  return CATEGORIES.has(category) ? category : 'scenario_failure';
}
function advanceCursor(state) {
  state.cursor = (state.cursor + 1) % SCENARIO_NAMES.length;
  if (state.cursor === 0) state.completedCycles++;
  state.retryAttempt = 0;
  state.nextAttemptAt = 0;
  state.currentScenario = null;
  state.currentRunId = null;
}
export function advanceState(input, result, nowMs) {
  const state = checkedState(structuredClone(input));
  if (state.status === 'blocked') return state;
  const category = categoryOf(result);
  state.heartbeatAt = nowMs;
  state.lastOutcome = category;
  if (!result.uploadRetry && result.headerPair != null) {
    const pair = checkedHeaderPair(result.headerPair, result.scenario);
    const previous = state.headerCadence[result.scenario];
    if (!pair || (previous.lastPairStartedAt !== null && pair.pairStartedAt < previous.lastPairStartedAt))
      throw failure('fatal_integrity');
    state.headerCadence[result.scenario] = {
      lastPairStartedAt: pair.pairStartedAt,
      lastPairCompletedAt: pair.pairCompletedAt,
      lastPairOutcome: pair.result,
    };
  }
  if (fatal(category)) {
    state.status = 'blocked';
    return state;
  }
  if (result?.uploadRetry) {
    const index = state.pendingUploads.findIndex((p) => p.runId === result.runId && p.scenario === result.scenario);
    if (index === -1) {
      state.status = 'blocked';
      state.lastOutcome = 'fatal_integrity';
      return state;
    }
    const pending = state.pendingUploads[index];
    state.currentRunId = null;
    state.currentScenario = null;
    if (category === 'busy') {
      state.busyCount++;
      state.status = 'busy';
      return state;
    }
    pending.attempts++;
    pending.exhausted = pending.attempts >= DEFAULT_POLICY.uploadAttempts;
    pending.nextAttemptAt = nowMs + DEFAULT_POLICY.backoffMs[Math.min(pending.attempts - 1, 2)];
    if (result.uploadCommitted === true && result.uploadExit === 0 && !result.signal) {
      state.pendingUploads.splice(index, 1);
      state.committedRuns++;
    }
    state.status = category === 'interrupted' ? 'interrupted' : 'idle';
    state.lastCompletedAt = nowMs;
    return state;
  }
  if (category === 'busy') {
    // Reservation is not an attempt: run.sh's sole flock returned before any browser work.
    if (state.status === 'running') {
      state.attemptedRuns--;
      state.retryAttempt--;
    }
    state.status = 'busy';
    state.busyCount++;
    state.currentRunId = null;
    state.currentScenario = null;
    return state;
  }
  if (state.status !== 'running') {
    state.attemptedRuns++;
    state.retryAttempt++;
  }
  state.lastCompletedAt = nowMs;
  if (category === 'ok' && browserPassed(result) && result.uploadExit === 0 && result.uploadCommitted === true) {
    state.browserPassedRuns++;
    state.committedRuns++;
    state.status = 'idle';
    advanceCursor(state);
    return state;
  }
  if (
    category === 'upload_transient' ||
    (['timeout', 'interrupted'].includes(category) && result.frozenEvidence === true && !result.uploadCommitted)
  ) {
    if (
      !RUN_ID.test(result.runId) ||
      !SCENARIO_NAMES.includes(result.scenario) ||
      state.pendingUploads.some((p) => p.runId === result.runId)
    ) {
      state.status = 'blocked';
      state.lastOutcome = 'fatal_integrity';
      return state;
    }
    if (state.pendingUploads.length >= DEFAULT_POLICY.maxPendingUploads) {
      state.status = 'blocked';
      state.lastOutcome = 'disk_blocked';
      return state;
    }
    state.pendingUploads.push({
      runId: result.runId,
      scenario: result.scenario,
      attempts: 0,
      nextAttemptAt: nowMs + DEFAULT_POLICY.backoffMs[0],
      exhausted: false,
      ...(HEADER_SCENARIO_SELECTORS[result.scenario]
        ? {
            headerPair: checkedHeaderPair(result.headerPair, result.scenario),
          }
        : {}),
    });
    if (browserPassed(result)) state.browserPassedRuns++;
    else state.failedRuns++;
    if (category === 'timeout') state.timeoutRuns++;
    if (category === 'interrupted') state.interruptedRuns++;
    state.status = category === 'interrupted' ? 'interrupted' : 'idle';
    advanceCursor(state);
    return state;
  }
  if (['target_transient', 'scenario_failure'].includes(category) && state.retryAttempt < DEFAULT_POLICY.maxAttempts) {
    state.status = 'backoff';
    state.nextAttemptAt =
      nowMs + Math.min(DEFAULT_POLICY.backoffMs[state.retryAttempt - 1], DEFAULT_POLICY.maxBackoffMs);
    state.currentRunId = null;
    state.currentScenario = null;
    return state;
  }
  state.failedRuns++;
  if (category === 'timeout') state.timeoutRuns++;
  if (category === 'interrupted') state.interruptedRuns++;
  state.status = category === 'interrupted' ? 'interrupted' : 'idle';
  advanceCursor(state);
  return state;
}

async function safePath(path, { directory = false, absent = false, rootOnly = false, changing = false } = {}) {
  const absolute = resolve(path);
  let current = '/';
  let info;
  for (const part of absolute.split('/').filter(Boolean)) {
    current = join(current, part);
    try {
      info = await lstat(current);
    } catch (error) {
      if (error.code === 'ENOENT' && absent && current === absolute) return null;
      throw failure('fatal_integrity');
    }
    if (
      info.isSymbolicLink() ||
      (!info.isDirectory() && current !== absolute) ||
      (!info.isDirectory() && !info.isFile()) ||
      (info.isFile() && info.nlink !== 1 && !(changing && current === absolute && info.nlink === 0))
    )
      throw failure('fatal_integrity');
    // Linux may return the just-unlinked inode when an active atomic writer replaces a file.
    // It is not a reachable hardlink; never relax checks on symlinks or ancestors.
    if (changing && current === absolute && info.isFile() && info.nlink === 0) return null;
    if (current === absolute && ((directory && !info.isDirectory()) || (rootOnly && info.uid !== 0)))
      throw failure('fatal_integrity');
  }
  return info;
}
async function smallJson(path, absent = false, changing = false) {
  const info = await safePath(path, { absent, changing });
  if (!info) return null;
  if (!info.isFile() || info.size > DEFAULT_POLICY.maxStateBytes) throw failure('fatal_integrity');
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const current = await handle.stat();
    if (
      (!changing && (current.dev !== info.dev || current.ino !== info.ino)) ||
      (current.nlink !== 1 && !(changing && current.nlink === 0)) ||
      !current.isFile() ||
      current.size > DEFAULT_POLICY.maxStateBytes
    )
      throw failure('fatal_integrity');
    if (changing) await safePath(dirname(path), { directory: true });
    return JSON.parse(await handle.readFile('utf8'));
  } catch (error) {
    if (changing && error.code === 'ENOENT' && !(await safePath(path, { absent: true, changing }))) return null;
    throw failure('fatal_integrity');
  } finally {
    await handle?.close();
  }
}
async function frozenEvidence(root, runId, scenario) {
  const run = join(root, runId);
  if (!(await safePath(run, { directory: true, absent: true }))) return false;
  const directory = join(run, scenario);
  if (!(await safePath(directory, { directory: true, absent: true }))) return false;
  for (const name of ['SHA256SUMS', 'upload-manifest.json', 'run-status.json']) {
    const info = await safePath(join(directory, name), { absent: true });
    if (!info) return false;
    if (!info.isFile() || !info.size) throw failure('fatal_integrity');
  }
  const manifest = await smallJson(join(directory, 'upload-manifest.json'));
  const status = await smallJson(join(directory, 'run-status.json'));
  if (
    manifest.schemaVersion !== 2 ||
    manifest.status !== 'pending' ||
    manifest.runId !== runId ||
    manifest.scenario !== scenario ||
    !manifest.objects ||
    typeof manifest.objects !== 'object' ||
    Array.isArray(manifest.objects) ||
    !Object.keys(manifest.objects).length ||
    !Number.isInteger(status.browserExit) ||
    status.browserExit < 0 ||
    status.browserExit > 255
  )
    throw failure('fatal_integrity');
  // The shell verifies the frozen checksum set before any retry can commit.
  return true;
}
async function prepareState(directory, live) {
  await safePath(dirname(directory), { directory: true, rootOnly: live });
  const info = await safePath(directory, { directory: true, absent: true, rootOnly: live });
  if (!info) await mkdir(directory, { mode: 0o700 });
  const verified = await safePath(directory, { directory: true, rootOnly: live });
  if (verified.mode & 0o077) throw failure('fatal_integrity');
}
async function saveState(directory, state) {
  const path = join(directory, 'state.json');
  await safePath(path, { absent: true });
  const temp = join(directory, `.state-${randomUUID()}.tmp`);
  const handle = await open(temp, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(checkedState(state))}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temp, path);
  const dir = await open(directory, 'r');
  try {
    await dir.sync();
  } finally {
    await dir.close();
  }
}
function pinnedCommand(binary, args) {
  const output = spawnSync(binary, args, {
    encoding: 'utf8',
    timeout: 10000,
    maxBuffer: DEFAULT_POLICY.maxOutputBytes,
    env: { PATH: '/usr/bin:/bin', HOME: '/root', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
  });
  if (output.status !== 0 || output.error) throw failure('fatal_provenance');
  return output.stdout.trim();
}
export function verifySourceTree(source, commit) {
  return (
    pinnedCommand('/usr/bin/git', ['-C', source, 'rev-parse', 'HEAD']) === commit &&
    pinnedCommand('/usr/bin/git', [
      '-c',
      'core.fileMode=false',
      '-C',
      source,
      'status',
      '--porcelain',
      '--untracked-files=no',
    ]) === ''
  );
}
async function verifyProvenance(config) {
  for (const path of [SOURCE, `${SOURCE}/suites/csd-violations`]) {
    const info = await safePath(path, { directory: true, rootOnly: true });
    if ((info.mode & 0o777) !== 0o555) throw failure('fatal_provenance');
  }
  for (const path of [
    RUN_SCRIPT,
    `${SOURCE}/suites/csd-violations/run.mjs`,
    `${SOURCE}/suites/csd-violations/continuous.mjs`,
    `${SOURCE}/suites/csd-violations/scenarios.mjs`,
  ]) {
    const info = await safePath(path, { rootOnly: true });
    if (!info.isFile() || (info.mode & 0o777) !== 0o444) throw failure('fatal_provenance');
  }
  if (!verifySourceTree(SOURCE, config.SOURCE_COMMIT)) return false;
  const digest = createHash('sha256')
    .update(await readFile(`${SOURCE}/suites/csd-violations/scenarios.mjs`))
    .digest('hex');
  const ready = await smallJson('/opt/traffic-generator/status.json');
  return (
    digest === config.DEPLOYMENT_MANIFEST_SHA256 &&
    ready?.status === 'ready' &&
    ready.source_commit === config.SOURCE_COMMIT &&
    ready.repository === config.SOURCE_REPOSITORY_URL &&
    ready.manifest?.sha256 === digest &&
    ready.manifest?.version === config.DEPLOYMENT_MANIFEST_VERSION
  );
}
export async function inventory(root, activeRunId = null) {
  await safePath(root, { directory: true });
  const runs = [];
  let visited = 0;
  async function size(path, active) {
    const info = await safePath(path, { absent: active, changing: active });
    if (!info) return 0;
    if (++visited > DEFAULT_POLICY.maxFiles) throw failure('disk_blocked');
    if (info.isFile()) return info.size;
    let bytes = 0;
    const names = await readdir(path);
    const current = await safePath(path, { directory: true });
    if (current.dev !== info.dev || current.ino !== info.ino) throw failure('fatal_integrity');
    for (const name of names) bytes += await size(join(path, name), active);
    return bytes;
  }
  for (const name of await readdir(root)) {
    if (!RUN_ID.test(name)) throw failure('fatal_integrity');
    const path = join(root, name);
    const info = await safePath(path, { directory: true });
    const bytes = await size(path, name === activeRunId);
    const result = await smallJson(join(path, 'execution-result.json'), true, name === activeRunId);
    const committed =
      result?.schemaVersion === 1 &&
      result.runId === name &&
      SCENARIO_NAMES.includes(result.scenario) &&
      result.uploadCommitted === true &&
      result.uploadExit === 0 &&
      Number.isInteger(result.browserExit) &&
      !result.signal;
    runs.push({ path, runId: name, bytes, modified: info.mtimeMs, committed });
  }
  return runs;
}
async function storageGate(root, state, now, adapters) {
  let runs = await inventory(root, state.currentRunId);
  const activeIds = new Set([state.currentRunId, ...state.pendingUploads.map((p) => p.runId)]);
  let total = runs.reduce((sum, run) => sum + run.bytes, 0);
  for (const run of runs
    .filter((r) => r.committed && !activeIds.has(r.runId))
    .sort((a, b) => a.modified - b.modified)) {
    if (now - run.modified <= DEFAULT_POLICY.retentionMs && total <= DEFAULT_POLICY.maxDetailBytes) continue;
    // Rewalk immediately before deletion: never follow a replaced symlink or delete active/pending evidence.
    await safePath(run.path, { directory: true });
    await inventory(root, state.currentRunId);
    await rm(run.path, { recursive: true });
    total -= run.bytes;
  }
  runs = await inventory(root, state.currentRunId);
  const pendingBytes = runs.filter((r) => !r.committed || activeIds.has(r.runId)).reduce((sum, r) => sum + r.bytes, 0);
  const disk = adapters.disk ? await adapters.disk(root) : await statfs(root);
  const free = disk.freeBytes ?? Number(disk.bavail) * Number(disk.bsize);
  if (
    !Number.isFinite(free) ||
    free < DEFAULT_POLICY.minFreeBytes ||
    total > DEFAULT_POLICY.maxDetailBytes ||
    pendingBytes > DEFAULT_POLICY.maxPendingBytes ||
    runs.some((r) => r.bytes > DEFAULT_POLICY.maxRunBytes)
  )
    throw failure('disk_blocked');
}
function validExecution(response, request) {
  if (response?.exitCode === 75)
    return {
      schemaVersion: 1,
      scenario: request.scenario,
      runId: request.runId,
      outcome: 'busy',
      failureCategory: 'busy',
      browserExit: null,
      uploadExit: null,
      uploadCommitted: false,
      signal: '',
    };
  const result = response?.result;
  if (!result) {
    const category =
      {
        64: 'fatal_config',
        65: 'fatal_integrity',
        66: 'fatal_integrity',
        67: 'fatal_target',
        69: 'fatal_config',
        77: 'fatal_auth',
        78: 'fatal_config',
      }[response?.exitCode] ?? 'scenario_failure';
    return {
      schemaVersion: 1,
      scenario: request.scenario,
      runId: request.runId,
      outcome: category,
      failureCategory: category,
      browserExit: null,
      uploadExit: null,
      uploadCommitted: false,
      signal: '',
    };
  }
  if (
    result.schemaVersion !== 1 ||
    result.scenario !== request.scenario ||
    result.runId !== request.runId ||
    !CATEGORIES.has(result.failureCategory || result.outcome) ||
    typeof result.uploadCommitted !== 'boolean' ||
    !['', 'TERM', 'INT', 'SIGTERM', 'SIGINT', 'KILL', 'SIGKILL'].includes(result.signal) ||
    ![result.browserExit, result.uploadExit].every((n) => n === null || (Number.isInteger(n) && n >= 0 && n <= 255))
  )
    throw failure('fatal_integrity');
  const headerPair = checkedHeaderPair(result.headerPair, request.scenario);
  if (headerPair && result.browserExit === 0 && headerPair.result !== 'passed') throw failure('fatal_integrity');
  if (
    request.uploadRetry &&
    HEADER_SCENARIO_SELECTORS[request.scenario] &&
    Object.keys(headerPair).some((key) => headerPair[key] !== request.headerPair?.[key])
  )
    throw failure('fatal_integrity');
  const category = categoryOf(result);
  if (
    (category === 'ok') !== (response.exitCode === 0) ||
    (category === 'ok' &&
      (result.browserExit !== 0 || result.uploadExit !== 0 || !result.uploadCommitted || result.signal)) ||
    (category === 'busy' && response.exitCode !== 75) ||
    (result.uploadCommitted && result.uploadExit !== 0)
  )
    throw failure('fatal_integrity');
  const fields = [
    'schemaVersion',
    'scenario',
    'runId',
    'outcome',
    'browserExit',
    'uploadExit',
    'uploadCommitted',
    'failureCategory',
    'signal',
    'headerPair',
  ];
  if (!exactKeys(result, fields)) throw failure('fatal_integrity');
  return { ...result, headerPair };
}
export function executionArgs(request) {
  const allowed = new Set([
    ...RUNTIME_KEYS,
    'PATH',
    'HOME',
    'RUNTIME_ENV',
    'RUN_ID',
    'CSD_SCENARIO',
    'RESULTS_ROOT',
    'RESULTS_DIR',
  ]);
  if (
    !RUN_ID.test(request.runId) ||
    !SCENARIO_NAMES.includes(request.scenario) ||
    request.env.RUN_ID !== request.runId ||
    request.env.CSD_SCENARIO !== request.scenario ||
    request.env.DISPLAY !== ':100'
  )
    throw failure('fatal_config');
  const assignments = Object.entries(request.env)
    .filter(([key]) => allowed.has(key))
    .map(([key, value]) => {
      if (typeof value !== 'string' || hasControlCharacters(value) || /\s/.test(value)) throw failure('fatal_config');
      return `${key}=${value}`;
    });
  return ['-u', 'tgen', '--', '/usr/bin/env', '-i', ...assignments, '/bin/bash', ...request.args];
}
async function executeOwned(request, signal, monitor) {
  if (signal?.aborted) throw failure('interrupted');
  return new Promise((resolvePromise) => {
    const child = spawn('/usr/bin/sudo', executionArgs(request), {
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: '/usr/bin:/bin', HOME: '/root' },
    });
    let bytes = 0;
    let category = null;
    let killTimer;
    let monitorTask = null;
    let closed = false;
    const groupSignal = (name) => {
      if (!Number.isInteger(child.pid) || child.pid <= 1) return;
      try {
        process.kill(-child.pid, name);
      } catch {
        /* already exited */
      }
    };
    const stop = (reason, name = 'SIGTERM') => {
      if (category) return;
      category = reason;
      groupSignal(name);
      killTimer = setTimeout(() => groupSignal('SIGKILL'), DEFAULT_POLICY.cleanupMs);
    };
    const onAbort = () => stop('interrupted');
    signal?.addEventListener('abort', onAbort, { once: true });
    const consume = (chunk) => {
      bytes += chunk.length;
      if (bytes > DEFAULT_POLICY.maxOutputBytes) stop('disk_blocked');
    };
    child.stdout.on('data', consume);
    child.stderr.on('data', consume);
    const deadline = setTimeout(() => stop('timeout'), request.timeoutMs);
    const interval = setInterval(() => {
      if (monitorTask || category || closed) return;
      monitorTask = monitor()
        .catch((error) => {
          stop(classify(error));
        })
        .finally(() => {
          monitorTask = null;
        });
    }, DEFAULT_POLICY.monitorMs);
    const cleanup = () => {
      clearTimeout(deadline);
      clearTimeout(killTimer);
      clearInterval(interval);
      signal?.removeEventListener('abort', onAbort);
    };
    child.once('error', () => {
      cleanup();
      resolvePromise({ exitCode: 1, category: 'fatal_config' });
    });
    child.once('close', async (exitCode, childSignal) => {
      closed = true;
      // Contain only owned descendants, then finish the outstanding atomic heartbeat.
      groupSignal('SIGKILL');
      cleanup();
      if (monitorTask) await monitorTask;
      resolvePromise({ exitCode: exitCode ?? 1, category: category || (childSignal ? 'interrupted' : null) });
    });
  });
}

export async function dispatchOnce(options = {}) {
  const adapters = options.adapters ?? {};
  const live = !Object.hasOwn(options, 'adapters');
  if (live && (options.config || options.stateDirectory || options.resultsRoot || options.now))
    throw failure('fatal_config');
  if (!live && !['verifyProvenance', 'execute', 'disk'].every((key) => typeof adapters[key] === 'function'))
    throw failure('fatal_config');
  const directory = options.stateDirectory ?? STATE_DIRECTORY;
  const root = options.resultsRoot ?? RESULTS_ROOT;
  const now = options.now ?? Date.now;
  let config;
  let state;
  let writable = false;
  try {
    await prepareState(directory, live);
    writable = true;
    const saved = await smallJson(join(directory, 'state.json'), true);
    // Replacement boot initializes state2; never rewrite or migrate an old worker's state.
    if (saved?.schemaVersion !== undefined && saved.schemaVersion !== 2) {
      writable = false;
      throw failure('fatal_provenance');
    }
    if (saved) state = checkedState(saved);
    if (state?.status === 'blocked') return state;
    if (live) {
      const info = await safePath(ENV_FILE, { rootOnly: true });
      if (info.mode & 0o022 || info.size > DEFAULT_POLICY.maxStateBytes) throw failure('fatal_config');
    }
    config = validateConfig(options.config ?? (await readFile(ENV_FILE, 'utf8')));
    state ??= freshState(config, now());
    if (state.sourceCommit !== config.SOURCE_COMMIT || state.manifestDigest !== config.DEPLOYMENT_MANIFEST_SHA256)
      throw failure('fatal_provenance');
    try {
      if (!(await (adapters.verifyProvenance ?? verifyProvenance)(config))) throw failure('fatal_provenance');
    } catch {
      throw failure('fatal_provenance');
    }
    if (config.CONTINUOUS_ENABLED === '0') return state;
    if (options.signal?.aborted) {
      state.status = 'interrupted';
      state.lastOutcome = 'interrupted';
      state.heartbeatAt = now();
      await saveState(directory, state);
      return state;
    }
    if (state.status === 'running') {
      // Persisted reservation is not proof of success. Reconcile once; never relaunch
      // its browser or credit an upload whose completion was not recorded.
      const uploadRetry = state.pendingUploads.some((p) => p.runId === state.currentRunId);
      const frozen = !uploadRetry && (await frozenEvidence(root, state.currentRunId, state.currentScenario));
      const runDirectory =
        !uploadRetry && (await safePath(join(root, state.currentRunId), { directory: true, absent: true }));
      const recorded = runDirectory && (await smallJson(join(root, state.currentRunId, 'execution-result.json'), true));
      const headerPair = recorded
        ? validExecution(
            { result: recorded, exitCode: categoryOf(recorded) === 'ok' ? 0 : 1 },
            { runId: state.currentRunId, scenario: state.currentScenario },
          ).headerPair
        : null;
      const recovery = {
        schemaVersion: 1,
        runId: state.currentRunId,
        scenario: state.currentScenario,
        outcome: 'interrupted',
        failureCategory: 'interrupted',
        browserExit: null,
        uploadExit: null,
        uploadCommitted: false,
        signal: 'TERM',
        uploadRetry,
        frozenEvidence: frozen,
        headerPair,
      };
      state = advanceState(state, recovery, now());
      if (uploadRetry) {
        state.currentRunId = null;
        state.currentScenario = null;
      }
      await saveState(directory, state);
      return state;
    }
    await storageGate(root, state, now(), adapters);
    const pending = state.pendingUploads.find((p) => !p.exhausted && p.nextAttemptAt <= now());
    if (!pending && state.pendingUploads.length >= DEFAULT_POLICY.maxPendingUploads) throw failure('disk_blocked');
    if (!pending && state.nextAttemptAt > now()) {
      state.heartbeatAt = now();
      await saveState(directory, state);
      return state;
    }
    const scenario = pending?.scenario ?? SCENARIO_NAMES[state.cursor];
    const runId = pending?.runId ?? `csd-${now()}-${randomUUID()}`;
    const args = [RUN_SCRIPT];
    if (pending) {
      const path = join(root, runId, scenario);
      await safePath(path, { directory: true });
      args.push('--retry-upload', path);
    }
    const env = {
      ...config,
      PATH: '/opt/node/bin:/usr/local/bin:/usr/bin:/bin',
      HOME: dirname(config.NODE_PATH),
      RUNTIME_ENV: ENV_FILE,
      RUN_ID: runId,
      CSD_SCENARIO: scenario,
      DISPLAY: ':100',
      RESULTS_ROOT: root,
      RESULTS_DIR: join(root, runId),
    };
    const request = {
      args,
      env,
      runId,
      scenario,
      uploadRetry: Boolean(pending),
      headerPair: pending?.headerPair ?? null,
      timeoutMs: pending ? DEFAULT_POLICY.uploadMs : DEFAULT_POLICY.scenarioMs + DEFAULT_POLICY.finalizationMs,
    };
    state.status = 'running';
    state.currentScenario = scenario;
    state.currentRunId = runId;
    if (!pending) {
      state.attemptedRuns++;
      state.retryAttempt++;
      state.lastStartedAt = now();
    }
    state.heartbeatAt = now();
    await saveState(directory, state);
    let response;
    try {
      response = await (adapters.execute ?? executeOwned)(request, options.signal, async () => {
        await storageGate(root, state, now(), adapters);
        state.heartbeatAt = now();
        await saveState(directory, state);
      });
    } catch (error) {
      response = { exitCode: 1, category: classify(error, 'scenario_failure') };
    }
    // Busy exits precede result writes; retry directories may contain an older result.
    if (response.exitCode === 75 && !response.category) response.result = null;
    else if (!response.result && (!response.category || ['timeout', 'interrupted'].includes(response.category))) {
      const runDirectory = await safePath(join(root, runId), { directory: true, absent: true });
      response.result = runDirectory ? await smallJson(join(root, runId, 'execution-result.json'), true) : null;
    }
    let result;
    if (response.category || options.signal?.aborted) {
      const recorded = response.result
        ? validExecution({ ...response, exitCode: categoryOf(response.result) === 'ok' ? 0 : 1 }, request)
        : validExecution(response, request);
      const category = fatal(response.category ?? '')
        ? response.category
        : recorded && fatal(categoryOf(recorded))
          ? categoryOf(recorded)
          : options.signal?.aborted
            ? 'interrupted'
            : response.category;
      result = {
        ...recorded,
        schemaVersion: 1,
        runId,
        scenario,
        outcome: category,
        failureCategory: category,
        browserExit: recorded?.browserExit ?? null,
        uploadExit: recorded?.uploadExit ?? null,
        uploadCommitted: false,
        signal: category === 'interrupted' ? 'TERM' : '',
      };
    } else result = validExecution(response, request);
    if (['timeout', 'interrupted'].includes(categoryOf(result)) && !result.uploadCommitted) {
      result = { ...result, frozenEvidence: await frozenEvidence(root, runId, scenario) };
    }
    if (pending) result = { ...result, uploadRetry: true };
    state = advanceState(state, result, now());
    await saveState(directory, state);
    return state;
  } catch (error) {
    state ??= freshState(config, now());
    state.status = 'blocked';
    state.lastOutcome = classify(error, 'fatal_config');
    state.heartbeatAt = now();
    if (writable) {
      try {
        await saveState(directory, state);
      } catch {
        /* unsafe state path is never overwritten */
      }
    }
    return state;
  }
}
export async function main(argv = process.argv.slice(2), options = {}) {
  const print = options.print ?? console.log;
  if (argv.length !== 1 || !['tick', 'status'].includes(argv[0])) throw failure('fatal_config');
  if (argv[0] === 'status') {
    let state;
    try {
      state = checkedState(await smallJson(join(options.stateDirectory ?? STATE_DIRECTORY, 'state.json')));
    } catch {
      state = freshState(null, Date.now());
      state.status = 'blocked';
      state.lastOutcome = 'fatal_integrity';
    }
    print(JSON.stringify(state));
    return state;
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.once('SIGINT', abort);
  process.once('SIGTERM', abort);
  try {
    return await dispatchOnce({ ...options, signal: options.signal ?? controller.signal });
  } finally {
    process.removeListener('SIGINT', abort);
    process.removeListener('SIGTERM', abort);
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main()
    .then((state) => {
      if (state.status === 'blocked') process.exitCode = 1;
    })
    .catch(() => {
      console.error('{"status":"blocked","lastOutcome":"fatal_config"}');
      process.exitCode = 1;
    });
}
