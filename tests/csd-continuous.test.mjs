import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  advanceState,
  DEFAULT_POLICY,
  dispatchOnce,
  executionArgs,
  inventory,
  main,
  validateConfig,
  verifySourceTree,
} from '../suites/csd-violations/continuous.mjs';
import { HEADER_SCENARIO_SELECTORS, SCENARIO_NAMES } from '../suites/csd-violations/scenarios.mjs';

const config = {
  TARGET_URL: 'https://client-side-defense.f5-sales-demo.com',
  CONTINUOUS_ENABLED: '1',
  SOURCE_COMMIT: 'a'.repeat(40),
  DEPLOYMENT_MANIFEST_SHA256: 'b'.repeat(64),
  SOURCE_REPOSITORY_URL: 'https://github.com/f5-sales-demo/traffic-generator.git',
  DEPLOYMENT_MANIFEST_VERSION: '1.1.0',
  CSD_AWS_RUNTIME: '1',
  AWS_REGION: 'us-east-1',
  AMI_ID: 'ami-0123456789abcdef0',
  EVIDENCE_BUCKET: 'synthetic-evidence',
  AWS_CLI_BIN: '/usr/local/bin/aws',
  AWS_CLI_VERSION: '2.27.49',
  NODE_PATH: '/opt/traffic-generator/node_modules',
  CHROME_BIN: '/opt/chrome/chrome',
  DISPLAY: ':99',
};
const initial = () => ({
  schemaVersion: 2,
  sourceCommit: config.SOURCE_COMMIT,
  manifestDigest: config.DEPLOYMENT_MANIFEST_SHA256,
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
  heartbeatAt: 0,
  lastOutcome: null,
  pendingUploads: [],
  headerCadence: Object.fromEntries(
    Object.keys(HEADER_SCENARIO_SELECTORS).map((name) => [
      name,
      {
        lastPairStartedAt: null,
        lastPairCompletedAt: null,
        lastPairOutcome: null,
      },
    ]),
  ),
});
const result = (category = 'ok', runId = 'csd-test', scenario = SCENARIO_NAMES[0]) => ({
  schemaVersion: 1,
  scenario,
  runId,
  outcome: category,
  browserExit: ['ok', 'upload_transient'].includes(category) ? 0 : 1,
  uploadExit: category === 'ok' ? 0 : 1,
  uploadCommitted: category === 'ok',
  failureCategory: category === 'ok' ? null : category,
  signal: '',
  headerPair: HEADER_SCENARIO_SELECTORS[scenario]
    ? {
        selector: HEADER_SCENARIO_SELECTORS[scenario],
        scope: 'same-origin',
        pairStartedAt: 1000,
        pairCompletedAt: 2000,
        result: ['ok', 'upload_transient'].includes(category) ? 'passed' : 'failed',
      }
    : null,
});
async function fixture(t, overrides = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'csd-continuous-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDirectory = join(root, 'state');
  const resultsRoot = join(root, 'results');
  await mkdir(stateDirectory, { mode: 0o700 });
  await mkdir(resultsRoot, { mode: 0o700 });
  let time = 100000;
  const calls = [];
  const options = {
    config,
    stateDirectory,
    resultsRoot,
    now: () => time,
    adapters: {
      verifyProvenance: async () => true,
      disk: async () => ({ freeBytes: 10 * 1024 ** 3 }),
      execute: async (r) => {
        calls.push(r);
        return { exitCode: 0, result: result('ok', r.runId, r.scenario) };
      },
      ...overrides,
    },
  };
  return {
    options,
    calls,
    stateDirectory,
    resultsRoot,
    setTime: (n) => {
      time = n;
    },
  };
}
const persist = (f, state) => writeFile(join(f.stateDirectory, 'state.json'), JSON.stringify(state));

test('strict parser, exact target, pinned config and enabled values', () => {
  assert.equal(validateConfig(config).CONTINUOUS_ENABLED, '1');
  for (const change of [
    { CONTINUOUS_ENABLED: 'true' },
    { SOURCE_COMMIT: '' },
    { TARGET_URL: `${config.TARGET_URL}/` },
    { AWS_CLI_BIN: '/bin/sh' },
  ])
    assert.throws(() => validateConfig({ ...config, ...change }));
  assert.throws(() => validateConfig('TARGET_URL=x\nTARGET_URL=y\n'));
  assert.throws(() => validateConfig('TARGET_URL=$(touch /tmp/not-a-test)\n'));
  assert.equal(
    validateConfig(
      Object.entries(config)
        .map(([k, v]) => `${k}=${v}`)
        .join('\n'),
    ).SOURCE_COMMIT,
    config.SOURCE_COMMIT,
  );
});
test('runtime values reject every ASCII control character in object and raw env input', () => {
  const raw = Object.entries(config)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  for (const code of [...Array(32).keys(), 127]) {
    const value = `safe${String.fromCharCode(code)}suffix`;
    assert.throws(() => validateConfig({ ...config, LOG_GROUP_NAME: value }), /fatal_config/);
    assert.throws(() => validateConfig(`${raw}\nLOG_GROUP_NAME=${value}`), /fatal_config/);
    assert.throws(
      () =>
        executionArgs({
          runId: 'csd-control',
          scenario: SCENARIO_NAMES[0],
          env: {
            ...config,
            RUN_ID: 'csd-control',
            CSD_SCENARIO: SCENARIO_NAMES[0],
            DISPLAY: ':100',
            LOG_GROUP_NAME: value,
          },
          args: [],
        }),
      /fatal_config/,
    );
  }
});
test('frozen fourteen-slot order wraps fourteen full cycles with all original eleven and three headers', () => {
  const original = [
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
  ];
  assert.deepEqual(SCENARIO_NAMES.slice(0, 11), original);
  assert.deepEqual(SCENARIO_NAMES.slice(11), Object.keys(HEADER_SCENARIO_SELECTORS));
  let state = initial();
  const visits = new Map();
  for (let i = 0; i < 14 * 14; i++) {
    const scenario = SCENARIO_NAMES[i % 14];
    assert.equal(state.cursor, i % 14);
    visits.set(scenario, (visits.get(scenario) ?? 0) + 1);
    state = advanceState(state, result('ok', `csd-${i}`, scenario), i + 1);
  }
  assert.equal(state.schemaVersion, 2);
  assert.equal(state.cursor, 0);
  assert.equal(state.completedCycles, 14);
  assert.equal(state.committedRuns, 196);
  assert.equal(state.browserPassedRuns, 196);
  assert.deepEqual([...visits.values()], Array(14).fill(14));
});
test('busy is not an attempted run or retry', () => {
  const state = advanceState(
    { ...initial(), status: 'running', attemptedRuns: 1, retryAttempt: 1 },
    result('busy'),
    10,
  );
  assert.equal(state.cursor, 0);
  assert.equal(state.retryAttempt, 0);
  assert.equal(state.attemptedRuns, 0);
  assert.equal(state.busyCount, 1);
});
test('transient retries bounded to three attempts and 30/60 second backoff', () => {
  for (const category of ['target_transient', 'scenario_failure']) {
    let state = advanceState(initial(), result(category), 1000);
    assert.equal(state.nextAttemptAt, 31000);
    assert.equal(state.cursor, 0);
    state = advanceState(state, result(category), 31000);
    assert.equal(state.nextAttemptAt, 91000);
    state = advanceState(state, result(category), 91000);
    assert.equal(state.cursor, 1);
    assert.equal(state.failedRuns, 1);
    assert.equal(state.retryAttempt, 0);
  }
});
test('fatal state never resets and interruption/unknown never count success', () => {
  const blocked = advanceState(initial(), result('fatal_auth'), 1);
  assert.equal(blocked.status, 'blocked');
  assert.deepEqual(advanceState(blocked, result(), 2), blocked);
  for (const category of ['interrupted', 'timeout', 'invented']) {
    const state = advanceState(initial(), result(category), 1);
    assert.equal(state.committedRuns, 0);
    assert.equal(state.browserPassedRuns, 0);
  }
});
test('provenance mismatch persists blocked state with no launch', async (t) => {
  const f = await fixture(t, { verifyProvenance: async () => false });
  assert.equal((await dispatchOnce(f.options)).lastOutcome, 'fatal_provenance');
  f.options.adapters.verifyProvenance = async () => true;
  assert.equal((await dispatchOnce(f.options)).status, 'blocked');
  assert.equal(f.calls.length, 0);
});
test('canonical run.sh, run-owned identity, :100 display and atomic state', async (t) => {
  const f = await fixture(t);
  const state = await dispatchOnce(f.options);
  assert.equal(state.cursor, 1);
  assert.equal(state.attemptedRuns, 1);
  assert.equal(f.calls[0].args[0], '/opt/traffic-generator/source/suites/csd-violations/run.sh');
  assert.equal(f.calls[0].env.DISPLAY, ':100');
  assert.equal(f.calls[0].env.HOME, '/opt/traffic-generator');
  assert.equal(f.calls[0].env.CSD_SCENARIO, SCENARIO_NAMES[0]);
  assert.equal(JSON.parse(await readFile(join(f.stateDirectory, 'state.json'))).committedRuns, 1);
});
test('missing or inconsistent result never succeeds', async (t) => {
  const f = await fixture(t, { execute: async () => ({ exitCode: 0 }) });
  assert.equal((await dispatchOnce(f.options)).committedRuns, 0);
  const g = await fixture(t, { execute: async (r) => ({ exitCode: 1, result: result('ok', r.runId, r.scenario) }) });
  assert.equal((await dispatchOnce(g.options)).status, 'blocked');
});
test('busy launch leaves cursor and retries unchanged', async (t) => {
  const f = await fixture(t, { execute: async () => ({ exitCode: 75 }) });
  const state = await dispatchOnce(f.options);
  assert.equal(state.cursor, 0);
  assert.equal(state.attemptedRuns, 0);
  assert.equal(state.retryAttempt, 0);
});
test('upload retry is one frozen shell retry not browser rerun or duplicate success', async (t) => {
  const f = await fixture(t, {
    execute: async (r) => ({ exitCode: 74, result: result('upload_transient', r.runId, r.scenario) }),
  });
  let state = await dispatchOnce(f.options);
  assert.equal(state.pendingUploads.length, 1);
  assert.equal(state.browserPassedRuns, 1);
  const pending = state.pendingUploads[0];
  await mkdir(join(f.resultsRoot, pending.runId, pending.scenario), { recursive: true });
  f.setTime(pending.nextAttemptAt);
  f.options.adapters.execute = async (r) => {
    f.calls.push(r);
    return { exitCode: 0, result: result('ok', r.runId, r.scenario) };
  };
  state = await dispatchOnce(f.options);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].args[1], '--retry-upload');
  assert.equal(state.browserPassedRuns, 1);
  assert.equal(state.committedRuns, 1);
  assert.equal(state.cursor, 1);
});
test('upload retry exhaustion stays visible with capped 30/60/120 delays', () => {
  let state = advanceState(initial(), result('upload_transient'), 1);
  for (let i = 0; i < 3; i++) {
    state = advanceState(state, { ...result('upload_transient'), uploadRetry: true }, 1000);
    assert.equal(state.pendingUploads[0].nextAttemptAt, 1000 + DEFAULT_POLICY.backoffMs[i]);
  }
  assert.equal(state.pendingUploads[0].exhausted, true);
  assert.equal(state.pendingUploads[0].attempts, 3);
  assert.equal(state.cursor, 1);
});
test('cancelled tick never launches and previous running reconciles without success', async (t) => {
  const f = await fixture(t);
  const controller = new AbortController();
  controller.abort();
  assert.equal((await dispatchOnce({ ...f.options, signal: controller.signal })).status, 'interrupted');
  assert.equal(f.calls.length, 0);
  await persist(f, {
    ...initial(),
    status: 'running',
    attemptedRuns: 1,
    retryAttempt: 1,
    currentRunId: 'csd-aborted',
    currentScenario: SCENARIO_NAMES[0],
  });
  const state = await dispatchOnce(f.options);
  assert.equal(state.interruptedRuns, 1);
  assert.equal(state.committedRuns, 0);
  assert.equal(state.cursor, 1);
  assert.equal(f.calls.length, 0);
});
test('previous interrupted upload consumes one retry not browser attempt', async (t) => {
  const f = await fixture(t);
  const pending = {
    runId: 'csd-pending',
    scenario: SCENARIO_NAMES[0],
    attempts: 0,
    nextAttemptAt: 0,
    exhausted: false,
  };
  await persist(f, {
    ...initial(),
    status: 'running',
    currentRunId: pending.runId,
    currentScenario: pending.scenario,
    pendingUploads: [pending],
  });
  const state = await dispatchOnce(f.options);
  assert.equal(state.pendingUploads[0].attempts, 1);
  assert.equal(state.attemptedRuns, 0);
  assert.equal(state.cursor, 0);
  assert.equal(state.committedRuns, 0);
  assert.equal(f.calls.length, 0);
});
test('free disk and full queue block new browser work', async (t) => {
  const f = await fixture(t, { disk: async () => ({ freeBytes: DEFAULT_POLICY.minFreeBytes - 1 }) });
  assert.equal((await dispatchOnce(f.options)).lastOutcome, 'disk_blocked');
  assert.equal(f.calls.length, 0);
  const g = await fixture(t);
  await persist(g, {
    ...initial(),
    pendingUploads: Array.from({ length: 32 }, (_, i) => ({
      runId: `csd-${i}`,
      scenario: SCENARIO_NAMES[0],
      attempts: 3,
      nextAttemptAt: 0,
      exhausted: true,
    })),
  });
  assert.equal((await dispatchOnce(g.options)).status, 'blocked');
  assert.equal(g.calls.length, 0);
});
test('finite per-run size blocks and never removes pending artifacts', async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.resultsRoot, 'csd-large'));
  const path = join(f.resultsRoot, 'csd-large', 'data');
  await writeFile(path, '');
  await truncate(path, DEFAULT_POLICY.maxRunBytes + 1);
  assert.equal((await dispatchOnce(f.options)).lastOutcome, 'disk_blocked');
  assert.equal(f.calls.length, 0);
  assert.ok(await readFile(join(f.stateDirectory, 'state.json')));
});
test('symlink state, retry, traversal and untrusted nested evidence rejected', async (t) => {
  const f = await fixture(t);
  await symlink(join(f.resultsRoot, 'missing'), join(f.stateDirectory, 'state.json'));
  assert.equal((await dispatchOnce(f.options)).lastOutcome, 'fatal_integrity');
  assert.equal(f.calls.length, 0);
  const g = await fixture(t);
  await persist(g, {
    ...initial(),
    pendingUploads: [
      { runId: '../outside', scenario: SCENARIO_NAMES[0], attempts: 0, nextAttemptAt: 0, exhausted: false },
    ],
  });
  assert.equal((await dispatchOnce(g.options)).status, 'blocked');
  assert.equal(g.calls.length, 0);
  const h = await fixture(t);
  await symlink('/tmp', join(h.resultsRoot, 'csd-link'));
  assert.equal((await dispatchOnce(h.options)).lastOutcome, 'fatal_integrity');
  assert.equal(h.calls.length, 0);
});
test('retention removes only old committed not frozen pending runs', async (t) => {
  const f = await fixture(t);
  for (const [id, committed] of [
    ['csd-old', true],
    ['csd-pending', false],
  ]) {
    await mkdir(join(f.resultsRoot, id));
    await writeFile(
      join(f.resultsRoot, id, 'execution-result.json'),
      JSON.stringify(result(committed ? 'ok' : 'upload_transient', id)),
    );
  }
  f.setTime(Date.now() + DEFAULT_POLICY.retentionMs + 10000);
  await dispatchOnce(f.options);
  await assert.rejects(readFile(join(f.resultsRoot, 'csd-old', 'execution-result.json')));
  assert.ok(await readFile(join(f.resultsRoot, 'csd-pending', 'execution-result.json')));
});
test('disabled config has no work and invalid source state blocks', async (t) => {
  const f = await fixture(t);
  assert.equal((await dispatchOnce({ ...f.options, config: { ...config, CONTINUOUS_ENABLED: '0' } })).attemptedRuns, 0);
  assert.equal(f.calls.length, 0);
  await persist(f, { ...initial(), sourceCommit: 'c'.repeat(40) });
  assert.equal((await dispatchOnce(f.options)).lastOutcome, 'fatal_provenance');
});
test('status is allowlisted, no raw config identities or error bodies', async (t) => {
  const f = await fixture(t, {
    verifyProvenance: async () => {
      throw new Error('secret account ARN');
    },
  });
  await dispatchOnce(f.options);
  let output = '';
  await main(['status'], {
    ...f.options,
    print: (s) => {
      output = s;
    },
  });
  assert.equal(JSON.parse(output).status, 'blocked');
  for (const forbidden of ['secret', 'ARN', config.EVIDENCE_BUCKET, config.AMI_ID, 'AWS_REGION'])
    assert.ok(!output.includes(forbidden));
});

test('pending two GiB subcap and total five GiB detail cap preserve evidence', async (t) => {
  for (const count of [9, 21]) {
    const f = await fixture(t);
    for (let i = 0; i < count; i++) {
      const dir = join(f.resultsRoot, `csd-cap-${i}`);
      await mkdir(dir);
      const path = join(dir, 'data');
      await writeFile(path, '');
      await truncate(path, DEFAULT_POLICY.maxRunBytes);
    }
    assert.equal((await dispatchOnce(f.options)).lastOutcome, 'disk_blocked');
    assert.equal(f.calls.length, 0);
    assert.ok(await readFile(join(f.resultsRoot, 'csd-cap-0', 'data')).then((data) => data.length > 0));
  }
});
test('abort during execution overrides optimistic success and cannot commit', async (t) => {
  const controller = new AbortController();
  const f = await fixture(t, {
    execute: async (r) => {
      controller.abort();
      return { exitCode: 0, result: result('ok', r.runId, r.scenario) };
    },
  });
  const state = await dispatchOnce({ ...f.options, signal: controller.signal });
  assert.equal(state.status, 'interrupted');
  assert.equal(state.committedRuns, 0);
  assert.equal(state.interruptedRuns, 1);
});
test('backoff tick launches nothing before deadline and unsafe adapters cannot execute live work', async (t) => {
  const f = await fixture(t);
  await persist(f, { ...initial(), status: 'backoff', nextAttemptAt: 200000, retryAttempt: 1 });
  assert.equal((await dispatchOnce(f.options)).attemptedRuns, 0);
  assert.equal(f.calls.length, 0);
  await assert.rejects(dispatchOnce({ ...f.options, adapters: {} }));
  await assert.rejects(dispatchOnce({ config }));
});

test('failed browser evidence can commit without becoming browser success', () => {
  const queued = advanceState(initial(), { ...result('upload_transient'), browserExit: 1 }, 1);
  const state = advanceState(
    queued,
    { ...result('scenario_failure'), uploadRetry: true, uploadCommitted: true, uploadExit: 0 },
    2,
  );
  assert.equal(state.pendingUploads.length, 0);
  assert.equal(state.committedRuns, 1);
  assert.equal(state.browserPassedRuns, 0);
  assert.equal(state.failedRuns, 1);
});

function command(binary, args, options = {}) {
  const response = spawnSync(binary, args, { encoding: 'utf8', ...options });
  assert.equal(response.status, 0, response.stderr || response.error?.message);
  return response.stdout.trim();
}
async function freeze(f, runId, scenario, browserExit = 0) {
  const directory = join(f.resultsRoot, runId, scenario);
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'payload.json'), '{}');
  await writeFile(
    join(directory, 'receipt.json'),
    JSON.stringify({
      schemaVersion: 3,
      runId,
      scenarios: [{ name: scenario, status: 'passed', steps: [] }],
    }),
  );
  // Real shell freeze/checksum generation: no AWS/browser/deployed paths are touched.
  command('/bin/bash', [
    fileURLToPath(new URL('../suites/csd-violations/run.sh', import.meta.url)),
    '--finalize-test',
    directory,
    runId,
    scenario,
  ]);
  // Freeze helper uses exit 0; create failed-browser metadata before freezing when needed.
  assert.equal(browserExit, 0);
  return directory;
}
test('real Git normalized tracked executables retain exact pinned content checks', async (t) => {
  const f = await fixture(t);
  const source = join(f.resultsRoot, 'git-source');
  await mkdir(source);
  command('/usr/bin/git', ['init', '-q', source]);
  await writeFile(join(source, 'runner.sh'), '#!/bin/bash\nexit 0\n');
  await chmod(join(source, 'runner.sh'), 0o755);
  command('/usr/bin/git', ['-C', source, 'add', 'runner.sh']);
  command('/usr/bin/git', [
    '-C',
    source,
    '-c',
    'user.name=Fixture',
    '-c',
    'user.email=fixture@example.com',
    'commit',
    '-qm',
    'fixture',
  ]);
  command('/usr/bin/git', ['-C', source, 'config', 'core.fileMode', 'true']);
  const commit = command('/usr/bin/git', ['-C', source, 'rev-parse', 'HEAD']);
  await chmod(join(source, 'runner.sh'), 0o444);
  assert.match(command('/usr/bin/git', ['-C', source, 'status', '--porcelain']), /runner.sh/); // reproduce old blocker
  assert.equal(verifySourceTree(source, commit), true);
  await chmod(join(source, 'runner.sh'), 0o644);
  await writeFile(join(source, 'runner.sh'), '#!/bin/bash\nexit 1\n');
  await chmod(join(source, 'runner.sh'), 0o444);
  assert.equal(verifySourceTree(source, commit), false);
  assert.equal(verifySourceTree(source, 'f'.repeat(40)), false);
});
test('real env subprocess preserves production argv assignments without inherited credentials', async () => {
  const env = {
    ...config,
    RUN_ID: 'csd-boundary',
    CSD_SCENARIO: SCENARIO_NAMES[0],
    DISPLAY: ':100',
    PATH: '/usr/bin:/bin',
    HOME: '/tmp',
    RUNTIME_ENV: '/etc/traffic-generator/runtime.env',
    AWS_SECRET_ACCESS_KEY: 'synthetic-secret',
    XCSH_API_TOKEN: 'synthetic-token',
  };
  const script = `printf "%s|%s|%s|%s|%s" "$RUN_ID" "$CSD_SCENARIO" "$DISPLAY" "\${AWS_SECRET_ACCESS_KEY-unset}" "\${XCSH_API_TOKEN-unset}"`;
  const args = executionArgs({ runId: env.RUN_ID, scenario: env.CSD_SCENARIO, env, args: ['-c', script] });
  assert.ok(!args.some((arg) => arg.includes('synthetic-secret') || arg.includes('synthetic-token')));
  assert.deepEqual(args.slice(0, 5), ['-u', 'tgen', '--', '/usr/bin/env', '-i']);
  // Execute the production env argv tail, not a fixture implementation of sanitization.
  const output = command(args[3], args.slice(4), { env });
  assert.equal(output, `${env.RUN_ID}|${env.CSD_SCENARIO}|:100|unset|unset`);
});
test('unknown credential/runtime keys fail closed at configuration gate', () => {
  for (const key of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'XCSH_API_TOKEN', 'BASH_ENV']) {
    assert.throws(() => validateConfig({ ...config, [key]: 'synthetic-value' }));
  }
});
test('busy upload collisions ignore stale results and never consume retries', async (t) => {
  const f = await fixture(t);
  const pending = {
    runId: 'csd-busy-upload',
    scenario: SCENARIO_NAMES[0],
    attempts: 0,
    nextAttemptAt: 0,
    exhausted: false,
  };
  await mkdir(join(f.resultsRoot, pending.runId, pending.scenario), { recursive: true });
  await writeFile(
    join(f.resultsRoot, pending.runId, 'execution-result.json'),
    JSON.stringify(result('upload_transient', pending.runId, pending.scenario)),
  );
  await persist(f, { ...initial(), cursor: 1, pendingUploads: [pending] });
  // Use an actual subprocess exit, not a synthetic result response.
  f.options.adapters.execute = async () => ({ exitCode: spawnSync('/bin/bash', ['-c', 'exit 75']).status });
  for (let i = 0; i < 4; i++) {
    const state = await dispatchOnce(f.options);
    assert.equal(state.pendingUploads[0].attempts, 0);
    assert.equal(state.pendingUploads[0].exhausted, false);
    assert.equal(state.cursor, 1);
    assert.equal(state.busyCount, i + 1);
    assert.equal(state.lastOutcome, 'busy');
  }
  // Even an unsafe prior result cannot mask the busy exit.
  await rm(join(f.resultsRoot, pending.runId, 'execution-result.json'));
  await symlink('/etc/passwd', join(f.resultsRoot, pending.runId, 'execution-result.json'));
  // Storage integrity is still checked before launching: symlinks never get ignored.
  assert.equal((await dispatchOnce(f.options)).lastOutcome, 'fatal_integrity');
});
test('known preflight subprocess exits without result block persistently', async (t) => {
  for (const [code, expected] of [
    [64, 'fatal_config'],
    [65, 'fatal_integrity'],
    [66, 'fatal_integrity'],
    [67, 'fatal_target'],
    [69, 'fatal_config'],
    [77, 'fatal_auth'],
    [78, 'fatal_config'],
  ]) {
    const f = await fixture(t, {
      execute: async () => ({ exitCode: spawnSync('/bin/bash', ['-c', `exit ${code}`]).status }),
    });
    const state = await dispatchOnce(f.options);
    assert.equal(state.status, 'blocked');
    assert.equal(state.lastOutcome, expected);
    assert.equal((await dispatchOnce(f.options)).attemptedRuns, state.attemptedRuns);
  }
  const f = await fixture(t, { execute: async () => ({ exitCode: spawnSync('/bin/bash', ['-c', 'exit 12']).status }) });
  assert.equal((await dispatchOnce(f.options)).lastOutcome, 'scenario_failure');
});
test('finalization timeout/interruption queue shell-frozen evidence and retry only upload', async (t) => {
  for (const category of ['timeout', 'interrupted']) {
    const f = await fixture(t);
    f.options.adapters.execute = async (r) => {
      await freeze(f, r.runId, r.scenario);
      const entry = {
        ...result(category, r.runId, r.scenario),
        browserExit: 0,
        uploadExit: category === 'timeout' ? 124 : 143,
        signal: category === 'interrupted' ? 'TERM' : '',
      };
      await writeFile(join(f.resultsRoot, r.runId, 'execution-result.json'), JSON.stringify(entry));
      return { exitCode: category === 'timeout' ? 124 : 143 };
    };
    let state = await dispatchOnce(f.options);
    assert.equal(state.pendingUploads.length, 1);
    assert.equal(state.browserPassedRuns, 1);
    assert.equal(state.committedRuns, 0);
    assert.equal(state.timeoutRuns + state.interruptedRuns, 1);
    const pending = state.pendingUploads[0];
    f.setTime(pending.nextAttemptAt);
    f.options.adapters.execute = async (r) => {
      assert.equal(r.args[1], '--retry-upload');
      assert.equal(r.runId, pending.runId);
      return { exitCode: 0, result: result('ok', r.runId, r.scenario) };
    };
    state = await dispatchOnce(f.options);
    assert.equal(state.pendingUploads.length, 0);
    assert.equal(state.committedRuns, 1);
    assert.equal(state.browserPassedRuns, 1);
  }
});
test('outer interruption and crash reconcile frozen evidence but cannot credit commit', async (t) => {
  const f = await fixture(t);
  f.options.adapters.execute = async (r) => {
    await freeze(f, r.runId, r.scenario);
    await writeFile(
      join(f.resultsRoot, r.runId, 'execution-result.json'),
      JSON.stringify({ ...result('timeout', r.runId, r.scenario), browserExit: 0, uploadExit: 124 }),
    );
    return { exitCode: 124, category: 'timeout' };
  };
  assert.equal((await dispatchOnce(f.options)).pendingUploads.length, 1);
  const g = await fixture(t);
  await freeze(g, 'csd-crash-frozen', SCENARIO_NAMES[0]);
  await persist(g, {
    ...initial(),
    status: 'running',
    attemptedRuns: 1,
    retryAttempt: 1,
    currentRunId: 'csd-crash-frozen',
    currentScenario: SCENARIO_NAMES[0],
  });
  const state = await dispatchOnce(g.options);
  assert.equal(state.pendingUploads.length, 1);
  assert.equal(state.committedRuns, 0);
  assert.equal(g.calls.length, 0);
});
test('browser timeout without frozen metadata remains failure, unsafe freeze blocks', async (t) => {
  const f = await fixture(t, {
    execute: async (r) => ({ exitCode: 124, result: result('timeout', r.runId, r.scenario) }),
  });
  const state = await dispatchOnce(f.options);
  assert.equal(state.pendingUploads.length, 0);
  assert.equal(state.timeoutRuns, 1);
  const g = await fixture(t);
  g.options.adapters.execute = async (r) => {
    const dir = await freeze(g, r.runId, r.scenario);
    await rm(join(dir, 'SHA256SUMS'));
    await symlink('/etc/passwd', join(dir, 'SHA256SUMS'));
    return { exitCode: 124, result: { ...result('timeout', r.runId, r.scenario), browserExit: 0, uploadExit: 124 } };
  };
  assert.equal((await dispatchOnce(g.options)).lastOutcome, 'fatal_integrity');
});
test('active inventory survives real atomic rename writers and rejects symlinks', async (t) => {
  const f = await fixture(t);
  const directory = join(f.resultsRoot, 'csd-writer');
  await mkdir(directory);
  const code = `const fs = require('node:fs'); const path = process.argv[1]; for (let i=0; i<10000; i++) { const tmp=path+'/payload.tmp-'+i; fs.writeFileSync(tmp, 'evidence'); fs.renameSync(tmp,path+'/payload'); const receipt=path+'/execution-result.json.tmp-'+i; fs.writeFileSync(receipt, JSON.stringify({schemaVersion:1,runId:'csd-writer',uploadCommitted:false})); fs.renameSync(receipt,path+'/execution-result.json'); }`;
  const child = spawn(process.execPath, ['-e', code, directory], { stdio: 'ignore' });
  const closed = once(child, 'close');
  let done = false;
  closed.then(() => {
    done = true;
  });
  let passes = 0;
  while (!done) {
    const entries = await inventory(f.resultsRoot, 'csd-writer');
    assert.equal(entries.length, 1);
    passes++;
  }
  assert.equal((await closed)[0], 0);
  assert.ok(passes > 1);
  await symlink('/etc/passwd', join(directory, 'unsafe'));
  await assert.rejects(inventory(f.resultsRoot, 'csd-writer'), /fatal_integrity/);
});

test('fatal preflight and recorded auth failures win concurrent cancellation', async (t) => {
  for (const recorded of ['category', 'result', 'missing']) {
    const controller = new AbortController();
    const f = await fixture(t, {
      execute: async (r) => {
        controller.abort();
        return recorded === 'result'
          ? { exitCode: 77, result: result('fatal_auth', r.runId, r.scenario) }
          : recorded === 'missing'
            ? { exitCode: 77 }
            : { exitCode: 1, category: 'fatal_provenance' };
      },
    });
    const state = await dispatchOnce({ ...f.options, signal: controller.signal });
    assert.equal(state.status, 'blocked');
    assert.equal(state.lastOutcome, recorded === 'category' ? 'fatal_provenance' : 'fatal_auth');
    assert.equal(state.pendingUploads.length, 0);
  }
});
test('active atomic-read tolerance never permits hardlinks or symlinked ancestors', async (t) => {
  const f = await fixture(t);
  const directory = join(f.resultsRoot, 'csd-hardlink');
  await mkdir(directory);
  await writeFile(join(directory, 'original'), 'evidence');
  await link(join(directory, 'original'), join(directory, 'alias'));
  await assert.rejects(inventory(f.resultsRoot, 'csd-hardlink'), /fatal_integrity/);
  await rm(directory, { recursive: true });
  await symlink('/tmp', directory);
  await assert.rejects(inventory(f.resultsRoot, 'csd-hardlink'), /fatal_integrity/);
});

test('all fourteen slots dispatch and persist browser-derived header epochs across reboot', async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < 14; i++) {
    f.setTime(100000 + i * 10000);
    const state = await dispatchOnce(f.options);
    assert.equal(state.cursor, (i + 1) % 14);
    assert.equal(state.lastOutcome, 'ok');
  }
  const saved = JSON.parse(await readFile(join(f.stateDirectory, 'state.json')));
  assert.equal(saved.schemaVersion, 2);
  assert.equal(saved.completedCycles, 1);
  assert.deepEqual(
    f.calls.map(({ scenario }) => scenario),
    SCENARIO_NAMES,
  );
  for (const entry of Object.values(saved.headerCadence)) {
    assert.deepEqual(entry, { lastPairStartedAt: 1000, lastPairCompletedAt: 2000, lastPairOutcome: 'passed' });
  }
  await dispatchOnce(f.options);
  assert.deepEqual(JSON.parse(await readFile(join(f.stateDirectory, 'state.json'))).headerCadence, saved.headerCadence);
});

test('header upload retries preserve frozen epochs and never rerun browser', async (t) => {
  const scenario = SCENARIO_NAMES[11];
  const f = await fixture(t, {
    execute: async (r) => ({
      exitCode: 1,
      result: result('upload_transient', r.runId, r.scenario),
    }),
  });
  await persist(f, { ...initial(), cursor: 11 });
  let state = await dispatchOnce(f.options);
  assert.equal(state.browserPassedRuns, 1);
  assert.equal(state.committedRuns, 0);
  const cadence = structuredClone(state.headerCadence);
  const pending = state.pendingUploads[0];
  assert.equal(pending.scenario, scenario);
  await mkdir(join(f.resultsRoot, pending.runId, scenario), { recursive: true });
  f.setTime(pending.nextAttemptAt);
  f.options.adapters.execute = async (r) => {
    assert.equal(r.args[1], '--retry-upload');
    f.calls.push(r);
    return { exitCode: 0, result: result('ok', r.runId, r.scenario) };
  };
  state = await dispatchOnce(f.options);
  assert.equal(f.calls.length, 1);
  assert.equal(state.cursor, 12);
  assert.equal(state.browserPassedRuns, 1);
  assert.equal(state.committedRuns, 1);
  assert.deepEqual(state.headerCadence, cadence);
});

test('invalid header execution summaries fail closed without inferred epochs or success', async (t) => {
  const scenario = SCENARIO_NAMES[11];
  const good = result('ok', 'csd-test', scenario).headerPair;
  for (const pair of [
    undefined,
    null,
    { ...good, selector: 'cache-control' },
    { ...good, scope: 'session' },
    { ...good, pairStartedAt: NaN },
    { ...good, pairCompletedAt: 999 },
    { ...good, pairCompletedAt: null },
    { ...good, result: 'failed' },
    { ...good, rawHeaders: 'forbidden' },
    { ...good, pairStartedAt: '1000' },
    { ...good, pairCompletedAt: Infinity },
  ]) {
    const f = await fixture(t, {
      execute: async (r) => ({ exitCode: 0, result: { ...result('ok', r.runId, r.scenario), headerPair: pair } }),
    });
    await persist(f, { ...initial(), cursor: 11 });
    const state = await dispatchOnce(f.options);
    assert.equal(state.lastOutcome, 'fatal_integrity');
    assert.equal(state.browserPassedRuns, 0);
    assert.equal(state.committedRuns, 0);
    assert.equal(state.headerCadence[scenario].lastPairStartedAt, null);
  }
});

test('failed partial pair timestamps survive interruption without fabricated completion', async (t) => {
  const scenario = SCENARIO_NAMES[12];
  const f = await fixture(t, {
    execute: async (r) => ({
      exitCode: 143,
      result: {
        ...result('interrupted', r.runId, r.scenario),
        signal: 'TERM',
        headerPair: { ...result('interrupted', r.runId, r.scenario).headerPair, pairCompletedAt: null },
      },
    }),
  });
  await persist(f, { ...initial(), cursor: 12 });
  const state = await dispatchOnce(f.options);
  assert.equal(state.interruptedRuns, 1);
  assert.equal(state.browserPassedRuns, 0);
  assert.deepEqual(state.headerCadence[scenario], {
    lastPairStartedAt: 1000,
    lastPairCompletedAt: null,
    lastPairOutcome: 'failed',
  });
});

test('header retry cannot replace frozen pair facts', async (t) => {
  const scenario = SCENARIO_NAMES[13];
  const queued = advanceState({ ...initial(), cursor: 13 }, result('upload_transient', 'csd-frozen', scenario), 1);
  const f = await fixture(t, {
    execute: async (r) => ({
      exitCode: 0,
      result: {
        ...result('ok', r.runId, r.scenario),
        headerPair: {
          ...result('ok', r.runId, r.scenario).headerPair,
          pairStartedAt: 3000,
          pairCompletedAt: 4000,
        },
      },
    }),
  });
  await persist(f, queued);
  await mkdir(join(f.resultsRoot, 'csd-frozen', scenario), { recursive: true });
  f.setTime(queued.pendingUploads[0].nextAttemptAt);
  const state = await dispatchOnce(f.options);
  assert.equal(state.lastOutcome, 'fatal_integrity');
  assert.deepEqual(state.headerCadence, queued.headerCadence);
  assert.equal(state.committedRuns, 0);
});

test('state1 cutover requires replacement and leaves old worker state untouched', async (t) => {
  const f = await fixture(t);
  const legacy = { ...initial(), schemaVersion: 1 };
  delete legacy.headerCadence;
  await persist(f, legacy);
  const before = await readFile(join(f.stateDirectory, 'state.json'), 'utf8');
  const state = await dispatchOnce(f.options);
  assert.equal(state.schemaVersion, 2);
  assert.equal(state.lastOutcome, 'fatal_provenance');
  assert.equal(f.calls.length, 0);
  assert.equal(await readFile(join(f.stateDirectory, 'state.json'), 'utf8'), before);
});

test('exact manifest version and source digest mismatch block browser dispatch', async (t) => {
  for (const version of ['1.0.0', '1.2.0', '1.1.1']) {
    assert.throws(() => validateConfig({ ...config, DEPLOYMENT_MANIFEST_VERSION: version }), /fatal_config/);
  }
  for (const change of [{ sourceCommit: 'c'.repeat(40) }, { manifestDigest: 'd'.repeat(64) }]) {
    const f = await fixture(t);
    await persist(f, { ...initial(), ...change });
    const state = await dispatchOnce(f.options);
    assert.equal(state.lastOutcome, 'fatal_provenance');
    assert.equal(f.calls.length, 0);
  }
});

test('crashed header reservation retains only actual recorded partial pair facts', async (t) => {
  const scenario = SCENARIO_NAMES[11];
  const f = await fixture(t);
  await persist(f, {
    ...initial(),
    status: 'running',
    cursor: 11,
    retryAttempt: 1,
    attemptedRuns: 1,
    currentScenario: scenario,
    currentRunId: 'csd-crash-header',
  });
  await mkdir(join(f.resultsRoot, 'csd-crash-header'));
  await writeFile(
    join(f.resultsRoot, 'csd-crash-header', 'execution-result.json'),
    JSON.stringify({
      ...result('interrupted', 'csd-crash-header', scenario),
      headerPair: { ...result('interrupted', 'csd-crash-header', scenario).headerPair, pairCompletedAt: null },
    }),
  );
  const state = await dispatchOnce(f.options);
  assert.equal(state.browserPassedRuns, 0);
  assert.equal(state.committedRuns, 0);
  assert.equal(f.calls.length, 0);
  assert.equal(state.headerCadence[scenario].lastPairStartedAt, 1000);
  assert.equal(state.headerCadence[scenario].lastPairCompletedAt, null);
});

test('state2 rejects malformed or raw cadence and preserves failed header retry epochs', async (t) => {
  const scenario = SCENARIO_NAMES[11];
  for (const entry of [
    undefined,
    { lastPairStartedAt: null, lastPairCompletedAt: 2000, lastPairOutcome: 'passed' },
    { lastPairStartedAt: 3000, lastPairCompletedAt: 2000, lastPairOutcome: 'failed' },
    { lastPairStartedAt: 1000, lastPairCompletedAt: null, lastPairOutcome: 'passed' },
    { lastPairStartedAt: 1000, lastPairCompletedAt: 2000, lastPairOutcome: 'passed', raw: 'forbidden' },
  ]) {
    const f = await fixture(t);
    const state = initial();
    state.headerCadence[scenario] = entry;
    await persist(f, state);
    assert.equal((await dispatchOnce(f.options)).lastOutcome, 'fatal_integrity');
    assert.equal(f.calls.length, 0);
  }
  let state = advanceState(
    { ...initial(), cursor: 11 },
    {
      ...result('upload_transient', 'csd-failed-header', scenario),
      browserExit: 1,
      headerPair: { ...result('scenario_failure', 'csd-failed-header', scenario).headerPair, pairCompletedAt: null },
    },
    10000,
  );
  const cadence = structuredClone(state.headerCadence);
  for (let i = 0; i < 3; i++) {
    state = advanceState(
      state,
      { ...result('upload_transient', 'csd-failed-header', scenario), uploadRetry: true, browserExit: 1 },
      20000 + i,
    );
    assert.deepEqual(state.headerCadence, cadence);
    assert.equal(state.browserPassedRuns, 0);
  }
  assert.equal(state.pendingUploads[0].exhausted, true);
  assert.equal(state.failedRuns, 1);
});
