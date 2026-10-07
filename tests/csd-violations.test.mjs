import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  aggregateDipOutcomes,
  boundedOperation,
  buildReceipt,
  createHeaderPairTracker,
  headerFacts,
  pageHelpers,
  projectHeaderPair,
  runHeaderPair,
  runSuite,
  sanitizeUrl,
  selectorRequestAllowed,
  validateAwsRuntime,
  validateTarget,
} from '../suites/csd-violations/run.mjs';
import {
  HEADER_SCENARIO_SELECTORS,
  HEADER_VALUES,
  PAYMENT_PATH,
  REVIEWED_DESTINATIONS,
  SCENARIO_NAMES,
  SCENARIOS,
  SUITE_MANIFEST,
} from '../suites/csd-violations/scenarios.mjs';

const expectedNames = [
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
const reviewedHosts = [
  'www.httpbin.org',
  'jsonplaceholder.typicode.com',
  'cdn.jsdelivr.net',
  'esm.sh',
  'unpkg.com',
  'ga.jspm.io',
];

const highVolumeOutcomeNames = [
  'scriptJsdelivr',
  'scriptEsm',
  'scriptUnpkg',
  'scriptJspm',
  'scriptChartjs',
  'postHttpbin',
  'postJsonplaceholder',
];
const terminalOutcomes = ['finished', 'blocked', 'failed', 'timed-out'];

test('manifest contains the exact stable eleven patterns and assertion contracts', () => {
  assert.deepEqual(SCENARIO_NAMES.slice(0, 11), expectedNames);
  assert.deepEqual(SCENARIO_NAMES.slice(11), Object.keys(HEADER_SCENARIO_SELECTORS));
  assert.equal(new Set(SCENARIO_NAMES).size, 14);
  assert.ok(SCENARIOS.every((scenario) => scenario.steps.every((step) => step.assertions?.length > 0)));
  assert.ok(SCENARIOS.slice(0, 11).every((scenario) => scenario.steps.at(-1)?.op === 'cleanup'));
  assert.ok(
    SCENARIOS.slice(0, 11).every((scenario) => {
      const fields = scenario.steps.at(-1).assertions.map(({ field }) => field);
      return [
        'artifactCount',
        'managedControlValueCount',
        'sensitiveValueCount',
        'timerCount',
        'listenerAttached',
      ].every((field) => fields.includes(field));
    }),
  );
  assert.deepEqual(
    Object.fromEntries(
      SCENARIOS.slice(0, 11).map(({ name, steps }) => [name, steps.find(({ op }) => op === 'navigate')?.route]),
    ),
    {
      'login-credential-skimmer': '/#/login',
      'registration-harvester': '/#/register',
      'payment-overlay-card-skimmer': '/#/login',
      'obfuscated-loader': '/',
      'multi-cdn-injection': '/',
      'tag-manager-hijack': '/',
      'multi-channel-exfiltration': '/#/login',
      'high-volume-domain-exfiltration': '/#/login',
      'form-overlay': '/#/login',
      'keylogger-simulation': '/#/login',
      'maximum-detection': '/#/login',
    },
  );
});

test('manifest publishes versioned safety and evidence contracts', () => {
  assert.match(SUITE_MANIFEST.schemaVersion, /^\d+\.\d+\.\d+$/);
  for (const field of [
    'displayName',
    'category',
    'preconditions',
    'syntheticDataPolicy',
    'immediateEvidence',
    'cleanup',
    'destinations',
    'screenshotRequirement',
    'claimBoundary',
  ])
    assert.ok(SUITE_MANIFEST[field], field);
  assert.ok(SCENARIOS.every((scenario) => scenario.displayName && scenario.claimBoundary));
  assert.ok(SCENARIOS.every((scenario) => Array.isArray(scenario.destinations)));
});

test('scenario matrix uses reviewed real destinations and no invalid hosts', async () => {
  assert.deepEqual(REVIEWED_DESTINATIONS, reviewedHosts);
  const source = await readFile(new URL('../suites/csd-violations/scenarios.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\.invalid|document\.cookie|localStorage|sessionStorage|authorization/i);
  for (const match of source.matchAll(/https:\/\/([^/'"`]+)/g)) assert.ok(reviewedHosts.includes(match[1]), match[1]);
  assert.match(source, /attempt-five-scripts-two-posts/);
  assert.match(source, /maskedDisplayOnly/);
  assert.match(source, /canonical-multi-cdn/);
});

test('high-volume scenario retains and asserts seven named sanitized terminal outcomes', async () => {
  const scenario = SCENARIOS.find(({ name }) => name === 'high-volume-domain-exfiltration');
  const step = scenario.steps.find(({ name }) => name === 'attempt-five-scripts-two-posts');
  const outcomeAssertions = step.assertions.filter(({ field }) => field.startsWith('outcomes.'));

  assert.deepEqual(
    outcomeAssertions.map(({ field }) => field.slice('outcomes.'.length)),
    highVolumeOutcomeNames,
  );
  assert.ok(outcomeAssertions.every(({ operator }) => operator === 'oneOf'));
  assert.ok(outcomeAssertions.every(({ value }) => value.join(',') === terminalOutcomes.join(',')));
  assert.ok(outcomeAssertions.every(({ value }) => !value.includes('pending')));
  assert.deepEqual(
    Object.fromEntries(
      step.assertions
        .filter(({ field }) => ['attemptCount', 'scriptCount', 'postCount', 'terminalCount'].includes(field))
        .map(({ field, value }) => [field, value]),
    ),
    { attemptCount: 7, scriptCount: 5, postCount: 2, terminalCount: 7 },
  );

  const runtimeSource = await readFile(new URL('../suites/csd-violations/run.mjs', import.meta.url), 'utf8');
  for (const name of highVolumeOutcomeNames) assert.match(runtimeSource, new RegExp(name));
  assert.match(runtimeSource, /Object\.values\(outcomes\)/);
  assert.doesNotMatch(runtimeSource, /outcomes\.(?:response|headers|body)/i);

  const docs = await readFile(new URL('../docs/en/05-suites.mdx', import.meta.url), 'utf8');
  for (const name of highVolumeOutcomeNames) assert.match(docs, new RegExp(`\\b${name}\\b`));
  for (const outcome of terminalOutcomes) assert.match(docs, new RegExp(`\\b${outcome}\\b`));
  assert.match(docs, /`pending` fails the assertion/);
});

test('target guard requires the exact HTTPS host', () => {
  assert.equal(
    validateTarget('https://client-side-defense.f5-sales-demo.com/#/login').hostname,
    'client-side-defense.f5-sales-demo.com',
  );
  for (const invalid of [
    'http://client-side-defense.f5-sales-demo.com',
    'https://client-side-defense.f5-sales-demo.com.evil.invalid',
    'https://other.f5-sales-demo.com',
    'https://user:password@client-side-defense.f5-sales-demo.com',
  ])
    assert.throws(() => validateTarget(invalid), /must be https:\/\/client-side-defense/);
});

test('obsolete unsafe CSD suites and helper test are removed', async () => {
  for (const relativePath of [
    '../suites/csd-demo-attacks/01-skimmer.js',
    '../suites/csd-detection/01-combined-detection.js',
    '../suites/csd-detection/population-result.cjs',
    '../suites/javascript-exploits/01-csd-formjacking.js',
    '../suites/javascript-exploits/02-csd-supply-chain.js',
    '../suites/javascript-exploits/03-csd-exfiltration.js',
    '../suites/javascript-exploits/04-csd-combined-stress.js',
    './csd-population-result.test.cjs',
  ])
    await assert.rejects(readFile(new URL(relativePath, import.meta.url)), /ENOENT/);
});

test('URL evidence redacts sensitive query values and removes fragments', () => {
  const sanitized = sanitizeUrl('https://example.invalid/path?email=a%40example.com&safe=yes&token=secret#fragment');
  assert.match(sanitized, /email=%5BREDACTED%5D/);
  assert.match(sanitized, /token=%5BREDACTED%5D/);
  assert.match(sanitized, /safe=yes/);
  assert.doesNotMatch(sanitized, /fragment|secret|a%40example\.com/);
});

test('receipt counts final screenshot and assertion failures', () => {
  const receipt = buildReceipt({
    runId: 'run-1',
    objectKey: 'runs/run-1/login-credential-skimmer/receipt.json',
    target: new URL('https://client-side-defense.f5-sales-demo.com'),
    startedAt: '2026-01-01T00:00:00.000Z',
    completedAt: '2026-01-01T00:01:00.000Z',
    scenarios: [
      {
        name: expectedNames[0],
        status: 'failed',
        steps: [
          {
            assertions: { status: 'failed' },
            screenshot: { status: 'failed', path: 'one.png' },
          },
        ],
        finalScreenshot: { status: 'failed', path: 'final.png' },
      },
    ],
    cleanup: { browser: 'closed', contexts: 1, errors: [] },
    runtime: {
      repository: 'https://github.com/f5-sales-demo/traffic-generator.git',
      sourceCommit: 'a'.repeat(40),
      chromeVersion: 'Chrome 140.0',
      nodeVersion: 'v22.0.0',
      amiId: 'ami-12345678',
      instanceId: 'i-12345678',
      region: 'us-east-1',
      manifestVersion: '1.0.0',
      manifestDigest: 'b'.repeat(64),
    },
  });
  assert.deepEqual(receipt.counts, {
    total: 1,
    passed: 0,
    failed: 1,
    steps: 1,
    screenshotFailures: 2,
    assertionFailures: 1,
  });
  assert.equal(receipt.schemaVersion, 3);
  assert.equal(receipt.manifest.schemaVersion, SUITE_MANIFEST.schemaVersion);
  assert.equal(receipt.discarded, false);
  assert.match(receipt.caveat, /not prove/);
  assert.equal(receipt.runtime.region, 'us-east-1');
  assert.equal(receipt.runtime.manifestDigest, 'b'.repeat(64));
  assert.equal(receipt.objectKey, 'runs/run-1/login-credential-skimmer/receipt.json');
});

test('runner records atomic receipt and screenshot evidence fields', async () => {
  const source = await readFile(new URL('../suites/csd-violations/run.mjs', import.meta.url), 'utf8');
  assert.match(source, /page\.screenshot\(\{ path: temporaryPath, type: 'png', fullPage: true \}\)/);
  assert.match(source, /rename\(temporaryPath, path\)/);
  assert.match(source, /rename\(temporaryPath, receiptPath\)/);
  assert.doesNotMatch(source, /--no-sandbox/);
  assert.match(source, /await rm\(temporaryPath, \{ force: true \}\)/);
  assert.match(source, /runs\/\$\{runId\}\/\$\{safeFilename\(scenarioName\)\}\/\$\{filename\}/);
  assert.match(source, /runs\/\$\{runId\}\/\$\{safeFilename\(selectedScenarios\[0\]\.name\)\}\/receipt\.json/);
  assert.match(source, /Object\.getOwnPropertyDescriptor\(HTMLInputElement\.prototype, 'value'\)/);
  assert.match(source, /data-csd-synthetic/);
  assert.match(source, /step\.op === 'evaluate' \|\| step\.op === 'cleanup'/);
  assert.match(source, /artifactCount/);
  assert.match(source, /managedControlValueCount/);
  assert.match(source, /sensitiveValueCount/);
  for (const field of [
    'startedAt',
    'completedAt',
    'sha256',
    'localPath',
    'objectKey',
    'captureStatus',
    'assertionStatus',
    'uploadStatus',
    'maskedInputCount',
    'repository',
    'sourceCommit',
    'chromeVersion',
    'nodeVersion',
    'amiId',
    'instanceId',
    'region',
    'manifestDigest',
  ])
    assert.match(source, new RegExp(field));
});

test('terminal fetch times out even when fetch ignores abort and removes its timer', async () => {
  const originalWindow = globalThis.window;
  const originalDocument = globalThis.document;
  const originalFetch = globalThis.fetch;
  globalThis.window = {};
  globalThis.document = {
    querySelector: () => null,
    querySelectorAll: () => [],
  };
  globalThis.fetch = () => new Promise(() => {});
  try {
    pageHelpers({ terminalTimeoutMs: 5 });
    const evidence = await globalThis.window.__csdSim.counterPost('https://www.httpbin.org/post', { count: 1 });
    assert.equal(evidence.terminal, 'timed-out');
    assert.equal((await globalThis.window.__csdSim.cleanupPage()).timerCount, 0);
  } finally {
    globalThis.window = originalWindow;
    globalThis.document = originalDocument;
    globalThis.fetch = originalFetch;
  }
});

test('cleanup clears only run-and-scenario managed controls after framework settlement', async () => {
  const globals = {
    window: globalThis.window,
    document: globalThis.document,
    HTMLInputElement: globalThis.HTMLInputElement,
    HTMLTextAreaElement: globalThis.HTMLTextAreaElement,
    HTMLSelectElement: globalThis.HTMLSelectElement,
    Event: globalThis.Event,
  };
  class FakeControl {
    constructor(type = 'text', value = '') {
      this.type = type;
      this.value = value;
      this.attributes = new Map();
      this.events = [];
    }
    setAttribute(name, value) {
      this.attributes.set(name, value);
    }
    getAttribute(name) {
      return this.attributes.get(name) ?? null;
    }
    removeAttribute(name) {
      this.attributes.delete(name);
    }
    dispatchEvent(event) {
      this.events.push(event.type);
      if (event.type === 'change' && this.resetOnce) {
        this.resetOnce = false;
        this.value = 'Synthetic-Only-Password-42!';
      }
      return true;
    }
  }
  class FakeInput extends FakeControl {}
  class FakeTextArea extends FakeControl {}
  class FakeSelect extends FakeControl {}
  const email = new FakeInput('email');
  const password = new FakeInput('password');
  const unrelated = new FakeInput('text', 'application-owned-value');
  const otherScenario = new FakeInput('text', 'other-scenario-value');
  const controls = [email, password, unrelated, otherScenario];
  const querySelectorAll = (selector) => {
    if (selector === '[data-csd-synthetic="true"]')
      return controls.filter((control) => control.getAttribute('data-csd-synthetic') === 'true');
    if (selector === 'input,textarea,select') return controls;
    return [];
  };
  globalThis.window = {};
  globalThis.HTMLInputElement = FakeInput;
  globalThis.HTMLTextAreaElement = FakeTextArea;
  globalThis.HTMLSelectElement = FakeSelect;
  globalThis.Event = class {
    constructor(type) {
      this.type = type;
    }
  };
  for (const prototype of [FakeInput.prototype, FakeTextArea.prototype, FakeSelect.prototype])
    Object.defineProperty(prototype, 'value', {
      get() {
        return this._value ?? '';
      },
      set(value) {
        this._value = value;
      },
      configurable: true,
    });
  for (const [control, value] of [
    [email, ''],
    [password, ''],
    [unrelated, 'application-owned-value'],
    [otherScenario, 'other-scenario-value'],
  ]) {
    delete control.value;
    control.value = value;
  }
  globalThis.document = {
    querySelector: (selector) => {
      if (selector.includes('email')) return email;
      if (selector.includes('password')) return password;
      return null;
    },
    querySelectorAll,
    removeEventListener: () => {},
  };
  try {
    pageHelpers();
    globalThis.window.__csdSim.beginScenario('run-1', 'login-credential-skimmer');
    assert.equal(globalThis.window.__csdSim.setSyntheticLogin().markerCount, 2);
    password.resetOnce = true;
    otherScenario.setAttribute('data-csd-synthetic', 'true');
    otherScenario.setAttribute('data-csd-run', 'run-1');
    otherScenario.setAttribute('data-csd-scenario', 'other-scenario');
    const result = await globalThis.window.__csdSim.cleanupPage();
    assert.equal(
      result.managedControlValueCount,
      0,
      JSON.stringify({ email: email.value, password: password.value, events: password.events }),
    );
    assert.equal(result.sensitiveValueCount, 0);
    assert.equal(unrelated.value, 'application-owned-value');
    assert.equal(otherScenario.value, 'other-scenario-value');
    assert.equal(email.getAttribute('data-csd-synthetic'), null);
    assert.equal(password.getAttribute('data-csd-synthetic'), null);
    for (const control of [email, password])
      assert.ok(['input', 'change', 'blur'].every((event) => control.events.includes(event)));
  } finally {
    Object.assign(globalThis, globals);
  }
});

test('navigation waits for delayed SPA route preconditions before evaluation', async () => {
  const outputDirectory = await mkdtemp(join(tmpdir(), 'csd-spa-wait-'));
  let ready = false;
  const waitedSelectors = [];
  const page = {
    on: () => {},
    goto: async () => ({ status: () => 200 }),
    waitForSelector: async (selector) => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      ready = true;
      waitedSelectors.push(selector);
    },
    evaluate: async (run) => {
      if (String(run).includes('setSyntheticLogin'))
        return ready ? { setCount: 2, markerCount: 2, syntheticOnly: true } : { setCount: 0, markerCount: 0 };
      if (String(run).includes('observeFields')) return { observedFieldCount: ready ? 2 : 0 };
      if (String(run).includes('counterPost')) return { postedCount: 2, terminal: 'finished' };
      return {
        artifactCount: 0,
        managedControlValueCount: 0,
        sensitiveValueCount: 0,
        timerCount: 0,
        listenerAttached: false,
      };
    },
    screenshot: async ({ path }) => writeFile(path, 'png'),
  };
  const playwright = {
    chromium: {
      launch: async () => ({
        newContext: async () => ({
          addInitScript: async () => {},
          newPage: async () => page,
          close: async () => {},
        }),
        close: async () => {},
      }),
    },
  };
  try {
    const result = await runSuite({
      playwright,
      outputDirectory,
      runId: 'spa-wait-run',
      scenario: 'login-credential-skimmer',
      targetUrl: 'https://client-side-defense.f5-sales-demo.com',
    });
    assert.deepEqual(waitedSelectors, [
      '#email, input[type="email"], input[name*="email" i], input[autocomplete="username"]',
      '#password, input[type="password"], input[autocomplete="current-password"]',
    ]);
    assert.equal(result.exitCode, 0);
  } finally {
    await rm(outputDirectory, { recursive: true, force: true });
  }
});

test('serialized receipt and local stderr never retain raw diagnostics', async () => {
  const secretError =
    'page said user@example.com password=hunter2 token=secret123 https://evil.invalid/path?email=user%40example.com&token=secret123';
  const outputDirectory = await mkdtemp(join(tmpdir(), 'csd-error-redaction-'));
  const stderr = [];
  const originalConsoleError = console.error;
  console.error = (message) => stderr.push(String(message));
  const playwright = {
    chromium: {
      launch: async () => ({
        newContext: async () => ({
          addInitScript: async () => {},
          newPage: async () => ({
            on: () => {},
            goto: async () => {
              throw new Error(secretError);
            },
            evaluate: async () => {
              throw new Error(secretError);
            },
            screenshot: async () => {
              throw new Error(secretError);
            },
          }),
          close: async () => {
            throw new Error(secretError);
          },
        }),
        close: async () => {
          throw new Error(secretError);
        },
      }),
    },
  };

  try {
    const result = await runSuite({
      playwright,
      outputDirectory,
      runId: 'redaction-run',
      scenario: expectedNames[0],
      targetUrl: 'https://client-side-defense.f5-sales-demo.com',
    });
    const serialized = JSON.stringify(result.receipt);
    assert.equal(result.exitCode, 1);
    assert.match(serialized, /STEP_EXECUTION_FAILED/);
    assert.match(serialized, /SCREENSHOT_CAPTURE_FAILED/);
    assert.match(serialized, /PAGE_CLEANUP_FAILED/);
    assert.match(serialized, /CONTEXT_CLEANUP_FAILED/);
    assert.match(serialized, /BROWSER_CLEANUP_FAILED/);
    assert.doesNotMatch(serialized, /user@example\.com|hunter2|secret123|evil\.invalid|page said/i);
    assert.ok(stderr.length > 0);
    assert.doesNotMatch(stderr.join('\n'), /user@example\.com|hunter2|secret123|evil\.invalid|page said/i);
  } finally {
    console.error = originalConsoleError;
    await rm(outputDirectory, { recursive: true, force: true });
  }
});

test('shell wrapper uses an immutable retryable upload commit protocol', async () => {
  const source = await readFile(new URL('../suites/csd-violations/run.sh', import.meta.url), 'utf8');
  assert.match(source, /RESULTS_ROOT=\/opt\/traffic-generator\/runtime\/results/);
  assert.match(source, /SCENARIO_DIR="\$\{RESULTS_DIR\}\/\$\{CSD_SCENARIO\}"/);
  assert.match(source, /--retry-upload/);
  assert.match(source, /upload_manifest_objects/);
  assert.match(source, /upload-commit\.json/);
  assert.match(source, /status:"committed"/);
  assert.match(source, /uploadStatus":"pending"/);
  assert.match(source, /sha256sum --check --strict SHA256SUMS/);
  assert.match(source, /remote_object_sha256/);
  assert.match(source, /s3api head-object/);
  assert.match(source, /--metadata "sha256=\$\{expected\}"/);
  assert.doesNotMatch(source, /list-objects-v2/);
  assert.doesNotMatch(source, /aws s3 cp "\$SCENARIO_DIR".*--recursive/);
  assert.doesNotMatch(source, /--sse(?:-kms-key-id)?/);
  assert.doesNotMatch(source, /set_receipt_upload_status/);
  assert.doesNotMatch(source, /\.uploadStatus =/);
  assert.match(source, /write_failure_marker/);
  assert.match(source, /commitUploaded:false/);
  assert.match(source, /read_runtime_env/);
  assert.doesNotMatch(source, /source "\$RUNTIME_ENV"/);
  assert.match(source, /CHROME_PATH=\/opt\/chrome\/chrome/);
  assert.doesNotMatch(source, /google-chrome|chromium-browser|command -v "\$candidate"/);
  assert.match(source, /AWS_CLI_BIN/);
  assert.match(source, /AWS_CLI_VERSION/);
  assert.match(source, /"\$AWS_CLI_BIN" --version 2>&1/);
  assert.match(source, /bounded_aws s3api head-object/);
  assert.match(source, /bounded_aws s3 cp/);
  assert.doesNotMatch(source, /command -v aws|(^|[^A-Z_])aws s3(api)? /m);
  assert.match(source, /trap 'on_signal TERM 143' TERM/);
  assert.match(source, /trap 'on_signal INT 130' INT/);
});

test('AWS runtime gate rejects local browser execution before launch', async () => {
  await assert.rejects(
    runSuite({
      targetUrl: 'https://client-side-defense.f5-sales-demo.com',
      executablePath: '/does/not/matter',
    }),
    /CSD_AWS_RUNTIME=1 is required|requires Linux; detected/,
  );
});

test('AWS runtime gate fails closed when deployment prerequisites are missing', async () => {
  await assert.rejects(
    validateAwsRuntime({ CSD_AWS_RUNTIME: '1' }, 'linux'),
    /SOURCE_COMMIT must be the exact deployed commit/,
  );
  await assert.rejects(
    validateAwsRuntime({ CSD_AWS_RUNTIME: '1', SOURCE_COMMIT: 'a'.repeat(40) }, 'darwin'),
    /requires Linux; detected darwin/,
  );
});

test('screenshot contract includes every explicit cleanup step and final state', () => {
  const stepCount = SCENARIOS.slice(0, 11).reduce((count, scenario) => count + scenario.steps.length, 0);
  const cleanupCount = SCENARIOS.slice(0, 11).reduce(
    (count, scenario) => count + scenario.steps.filter(({ op }) => op === 'cleanup').length,
    0,
  );
  assert.equal(cleanupCount, 11);
  assert.equal(stepCount, 45);
  assert.equal(stepCount + 11, 56);
});

test('AWS headed Chrome captures every step and final screenshot', {
  skip:
    process.env.CSD_AWS_RUNTIME === '1' && process.platform === 'linux'
      ? false
      : 'AWS-only: requires CSD_AWS_RUNTIME=1 on Linux',
  timeout: 300_000,
}, async () => {
  const outputDirectory = process.env.CSD_AWS_OUTPUT_DIR;
  const result = await runSuite({ outputDirectory });
  const expectedScreenshotCount = SCENARIOS.reduce((count, scenario) => count + scenario.steps.length + 1, 0);
  assert.equal(
    result.receipt.scenarios
      .flatMap((scenario) => [...scenario.steps.map((step) => step.screenshot), scenario.finalScreenshot])
      .filter((shot) => shot.status === 'captured').length,
    expectedScreenshotCount,
  );
  assert.equal(result.receipt.cleanup.browser, 'closed');
  assert.equal(result.exitCode, 0);
  assert.ok(result.receipt.scenarios.every((scenario) => scenario.finalScreenshot.status === 'captured'));
});

test('bounded operations reject timeout and cancellation without waiting for an uncooperative adapter', async () => {
  await assert.rejects(
    boundedOperation(() => new Promise(() => {}), 5),
    /OPERATION_TIMEOUT/,
  );
  const controller = new AbortController();
  const pending = boundedOperation(() => new Promise(() => {}), 10_000, controller.signal);
  controller.abort();
  await assert.rejects(pending, /RUN_INTERRUPTED/);
  await assert.rejects(
    boundedOperation(() => 1, 5, controller.signal),
    /RUN_INTERRUPTED/,
  );
});

test('cancellation stops new steps, bounds failed cleanup, and preserves a failed receipt', async () => {
  const outputDirectory = await mkdtemp(join(tmpdir(), 'csd-cancel-'));
  const controller = new AbortController();
  let navigations = 0;
  const page = {
    on() {},
    goto: async () => {
      navigations++;
      controller.abort();
      return { status: () => 200 };
    },
    evaluate: async () => new Promise(() => {}),
    screenshot: async () => new Promise(() => {}),
  };
  const playwright = {
    chromium: {
      launch: async () => ({
        newContext: async () => ({
          addInitScript: async () => {},
          newPage: async () => page,
          close: async () => new Promise(() => {}),
        }),
        close: async () => new Promise(() => {}),
      }),
    },
  };
  try {
    const result = await runSuite({
      playwright,
      outputDirectory,
      scenario: SCENARIO_NAMES[0],
      runId: 'cancel-run',
      targetUrl: 'https://client-side-defense.f5-sales-demo.com',
      signal: controller.signal,
      cleanupDeadline: () => Date.now() + 5,
    });
    assert.equal(navigations, 1);
    assert.equal(result.exitCode, 143);
    assert.equal(result.receipt.cleanup.browser, 'failed');
    assert.equal(result.receipt.scenarios[0].status, 'failed');
    assert.equal(JSON.parse(await readFile(result.receiptPath, 'utf8')).counts.passed, 0);
  } finally {
    await rm(outputDirectory, { recursive: true, force: true });
  }
});

test('one shared lock and external execution result govern browser and upload retry', async () => {
  const source = await readFile(new URL('../suites/csd-violations/run.sh', import.meta.url), 'utf8');
  assert.equal((source.match(/flock -n 9/g) ?? []).length, 1);
  assert.match(source, /LOCK_PATH=\/run\/lock\/csd-traffic-generator.lock/);
  assert.match(source, /execution-result.json/);
  assert.match(source, /schemaVersion:1,scenario:\$scenario,runId:\$runId,outcome:\$outcome/);
  assert.match(source, /uploadCommitted:\$uploadCommitted,failureCategory:\$failureCategory,signal:\$signal/);
  assert.match(source, /realpath -m/);
  assert.match(source, /SCENARIO_NAMES.includes/);
  assert.doesNotMatch(source, /pkill|killall|login-credential-skimmer \| registration/);
  assert.match(source, /timeout --foreground --signal=TERM --kill-after="\$CLEANUP_SECONDS" "\$SCENARIO_SECONDS"/);
  assert.match(source, /timeout --signal=TERM --kill-after=2 "\$budget"/);
  assert.match(source, /DEFAULT_POLICY: p/);
});

test('real Chrome reverses owned native controls after asynchronous rehydration', {
  skip: !process.env.CSD_TEST_CHROME_PATH || !process.env.CSD_TEST_PLAYWRIGHT_MODULE,
}, async () => {
  const { chromium } = await import(process.env.CSD_TEST_PLAYWRIGHT_MODULE);
  const browser = await chromium.launch({ executablePath: process.env.CSD_TEST_CHROME_PATH, headless: true });
  try {
    const page = await browser.newPage();
    await page.setContent(`
      <input id="emailControl" type="email"><input id="passwordControl" type="password">
      <input id="toggle" type="checkbox"><input id="radio" type="radio">
      <textarea id="answer"></textarea><select id="question"><option value="">Choose</option></select>
      <input id="foreign" value="application-owned"><input id="other" type="checkbox" checked>
    `);
    await page.evaluate(pageHelpers, { runId: 'browser-regression', scenarioName: 'registration-harvester' });
    await page.evaluate(() => {
      const foreign = document.querySelector('#foreign');
      const other = document.querySelector('#other');
      foreign.remove();
      other.remove();
      window.__csdSim.setSyntheticRegistration();
      const select = document.querySelector('#question');
      select.setAttribute('data-csd-synthetic', 'true');
      select.setAttribute('data-csd-run', 'browser-regression');
      select.setAttribute('data-csd-scenario', 'registration-harvester');
      document.body.append(foreign, other);
      other.setAttribute('data-csd-synthetic', 'true');
      other.setAttribute('data-csd-run', 'different-run');
      other.setAttribute('data-csd-scenario', 'registration-harvester');
      window.controlEvents = [];
      const owned = [...document.querySelectorAll('[data-csd-run="browser-regression"]')];
      for (const control of owned) {
        for (const name of ['input', 'change', 'blur']) {
          control.addEventListener(name, () => window.controlEvents.push(name));
        }
        control.addEventListener('change', () => {
          if (control.dataset.resetDone) return;
          control.dataset.resetDone = 'true';
          setTimeout(() => {
            if (control.type === 'checkbox' || control.type === 'radio') control.checked = true;
            else if (control.tagName === 'SELECT') control.selectedIndex = 0;
            else control.value = 'synthetic-framework-rehydration';
          }, 10);
        });
      }
    });
    const cleanup = await page.evaluate(() => window.__csdSim.cleanupPage());
    assert.deepEqual(cleanup, {
      artifactCount: 0,
      managedControlValueCount: 0,
      sensitiveValueCount: 0,
      timerCount: 0,
      listenerAttached: false,
    });
    const state = await page.evaluate(() => ({
      owned: [...document.querySelectorAll('#emailControl,#passwordControl,#toggle,#radio,#answer,#question')].map(
        (control) => ({
          value: control.value,
          checked: control.checked ?? false,
          selectedIndex: control.selectedIndex ?? -1,
          marked: control.hasAttribute('data-csd-synthetic'),
        }),
      ),
      foreign: document.querySelector('#foreign').value,
      otherChecked: document.querySelector('#other').checked,
      events: [...new Set(window.controlEvents)].sort(),
    }));
    assert.ok(
      state.owned.every(
        (control) => !control.value && !control.checked && control.selectedIndex === -1 && !control.marked,
      ),
    );
    assert.equal(state.foreign, 'application-owned');
    assert.equal(state.otherChecked, true);
    assert.deepEqual(state.events, ['blur', 'change', 'input']);
    await page.evaluate(() => {
      const toggle = document.querySelector('#toggle');
      toggle.setAttribute('data-csd-synthetic', 'true');
      toggle.setAttribute('data-csd-run', 'browser-regression');
      toggle.setAttribute('data-csd-scenario', 'registration-harvester');
      toggle.addEventListener('change', () => {
        toggle.checked = true;
      });
    });
    const retained = await page.evaluate(() => window.__csdSim.cleanupPage());
    assert.equal(retained.managedControlValueCount, 1);
    assert.equal(await page.locator('#toggle').getAttribute('data-csd-synthetic'), 'true');
    await page.evaluate(() => {
      const toggle = document.querySelector('#toggle');
      toggle.removeAttribute('data-csd-synthetic');
      toggle.checked = false;
      const select = document.querySelector('#question');
      select.setAttribute('data-csd-synthetic', 'true');
      select.setAttribute('data-csd-run', 'browser-regression');
      select.setAttribute('data-csd-scenario', 'registration-harvester');
      select.addEventListener('change', () => {
        select.selectedIndex = 0;
      });
    });
    const selected = await page.evaluate(() => window.__csdSim.cleanupPage());
    assert.equal(selected.managedControlValueCount, 1);
    assert.equal(await page.locator('#question').getAttribute('data-csd-synthetic'), 'true');
  } finally {
    await browser.close();
  }
});

const paymentUrl = `https://client-side-defense.f5-sales-demo.com${PAYMENT_PATH}`;
const targetOrigin = new URL('https://client-side-defense.f5-sales-demo.com');

test('fourteen frozen scenarios append only the exact three header omissions', () => {
  assert.equal(SUITE_MANIFEST.schemaVersion, '1.1.0');
  assert.equal(SCENARIOS.length, 14);
  for (const scenario of SCENARIOS.slice(11)) {
    assert.ok(Object.isFrozen(scenario));
    assert.ok(Object.isFrozen(scenario.steps));
    assert.ok(Object.isFrozen(scenario.steps[0]));
    assert.equal(scenario.kind, 'header-pair');
    assert.equal(scenario.steps[0].scope, 'same-origin');
    assert.equal(scenario.steps[0].route, PAYMENT_PATH);
    assert.equal(scenario.steps[0].selector, HEADER_SCENARIO_SELECTORS[scenario.name]);
  }
});

test('selector guards exact raw URL and excludes redirects, collectors, preflight and non-read verbs', () => {
  const allowed = { url: paymentUrl, method: 'GET', resourceType: 'Document' };
  assert.equal(selectorRequestAllowed(allowed, targetOrigin), true);
  assert.equal(selectorRequestAllowed({ ...allowed, method: 'HEAD', resourceType: 'Fetch' }, targetOrigin), true);
  assert.equal(selectorRequestAllowed({ ...allowed, method: 'HEAD' }, targetOrigin, 'document'), false);
  assert.equal(selectorRequestAllowed({ ...allowed, resourceType: 'Script' }, targetOrigin, 'document'), false);
  assert.equal(selectorRequestAllowed({ ...allowed, redirectedRequestId: 'private-id' }, targetOrigin), false);
  for (const method of ['POST', 'OPTIONS', 'PUT', 'get', 'DELETE'])
    assert.equal(selectorRequestAllowed({ ...allowed, method }, targetOrigin), false);
  for (const url of [
    paymentUrl + '?',
    paymentUrl + '#',
    paymentUrl + '?email=private',
    paymentUrl + '/',
    paymentUrl.replace('/payment', '/%70ayment'),
    paymentUrl.replace('/payment', '/x/../payment'),
    paymentUrl.replace('/payment', '//payment'),
    paymentUrl.replace('https://', 'http://'),
    paymentUrl.replace('https://', 'https://user:secret@'),
    paymentUrl.replace('.com/', '.com:443/'),
    paymentUrl.replace('client-side-defense', 'CLIENT-SIDE-DEFENSE'),
    paymentUrl.replace('/csd-page-tamper/payment', '/__imp_apg__/api/dip/v1/dip'),
    'https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip',
    paymentUrl.replace('.com/', '.com.evil.invalid/'),
  ])
    assert.equal(selectorRequestAllowed({ ...allowed, url }, targetOrigin), false, url);
  assert.equal(selectorRequestAllowed({ ...allowed, resourceType: 'Preflight' }, targetOrigin), false);
  assert.equal(selectorRequestAllowed(allowed, targetOrigin, 'all-assets'), false);
  assert.equal(
    selectorRequestAllowed(
      { url: () => paymentUrl, method: () => 'GET', resourceType: () => 'document', redirectedFrom: () => null },
      targetOrigin,
    ),
    true,
  );
});

test('case-insensitive frozen header facts reject duplicate and ambiguous wire values', () => {
  assert.deepEqual(
    headerFacts({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store, max-age=0',
    }),
    headerFacts(HEADER_VALUES),
  );
  assert.equal(headerFacts({ ...HEADER_VALUES, 'X-Frame-Options': 'DENY' }), null);
  assert.equal(headerFacts({ ...HEADER_VALUES, 'x-frame-options': 'DENY\nDENY' }), null);
  assert.equal(headerFacts({ ...HEADER_VALUES, 'cache-control': ['no-store'] }), null);
  assert.equal(headerFacts([]), null);
  assert.equal(
    headerFacts({ ...HEADER_VALUES, 'x-frame-options': 'DENY, DENY' })['x-frame-options'].matchesCanonical,
    false,
  );
});

function wireEvent(
  tracker,
  {
    id = 'private-document',
    method = 'GET',
    type = 'Document',
    url = paymentUrl,
    selector = null,
    headers = HEADER_VALUES,
    status = 200,
    initiator = 'script',
    finished = true,
    extra = true,
    duplicate = false,
  } = {},
) {
  const request = { url, method, headers: selector ? { 'X-CSD-Page-Tamper': selector } : {} };
  tracker.event('Network.requestWillBeSentExtraInfo', { requestId: id, headers: request.headers });
  tracker.event('Network.responseReceivedExtraInfo', { requestId: id, statusCode: status, headers });
  tracker.event('Network.requestWillBeSent', {
    requestId: id,
    request,
    type,
    frameId: 'private-top-frame',
    initiator: { type: initiator },
  });
  tracker.event('Network.responseReceived', { requestId: id, hasExtraInfo: extra, response: { url, status, headers } });
  if (duplicate) tracker.event('Network.responseReceivedExtraInfo', { requestId: id, statusCode: status, headers });
  if (finished) tracker.event('Network.loadingFinished', { requestId: id });
}

test('wire ExtraInfo ambiguity, unknown status and fake HEAD provenance never establish observations', () => {
  const value = (tracker) =>
    tracker.value({
      mode: 'control',
      scope: 'same-origin',
      topFrameId: 'private-top-frame',
      naturalHeadObserved: true,
      documentStatus: 200,
      headStatus: 200,
    });
  const tracker = createHeaderPairTracker(targetOrigin, 'x-content-type-options');
  wireEvent(tracker);
  wireEvent(tracker, { id: 'private-head', method: 'HEAD', type: 'Fetch' });
  assert.equal(value(tracker).document.observed, true);
  assert.equal(value(tracker).head.observed, true);
  assert.equal(
    tracker.value({
      mode: 'control',
      scope: 'same-origin',
      topFrameId: 'private-top-frame',
      naturalHeadObserved: false,
      documentStatus: 200,
      headStatus: 200,
    }).head.observed,
    false,
  );
  for (const args of [{ extra: false }, { duplicate: true }, { status: null }, { finished: false }]) {
    const candidate = createHeaderPairTracker(targetOrigin, 'x-content-type-options');
    wireEvent(candidate, args);
    if (args.duplicate) assert.equal(value(candidate).invalid, true);
    assert.equal(value(candidate).document.observed, false);
  }
  const fabricated = createHeaderPairTracker(targetOrigin, 'x-content-type-options');
  wireEvent(fabricated, { id: 'head', method: 'HEAD', type: 'Fetch', initiator: 'other' });
  assert.equal(value(fabricated).head.observed, false);
  const serialized = JSON.stringify(value(tracker));
  assert.doesNotMatch(serialized, /private-document|private-head|private-top-frame|nosniff|no-store|DENY/);
});

test('HEAD wire observation accepts only exact canceled-after-response ERR_ABORTED evidence', () => {
  const observe = (failure, setup = {}) => {
    const tracker = createHeaderPairTracker(targetOrigin, 'x-content-type-options');
    wireEvent(tracker, { id: 'head', method: 'HEAD', type: 'Fetch', finished: false, ...setup });
    tracker.event('Network.loadingFailed', { requestId: 'head', ...failure });
    return tracker.value({
      mode: 'control',
      scope: 'same-origin',
      topFrameId: 'private-top-frame',
      naturalHeadObserved: true,
      documentStatus: 200,
      headStatus: 200,
    });
  };
  const accepted = observe({ canceled: true, errorText: 'net::ERR_ABORTED' });
  assert.equal(accepted.head.observed, true);
  assert.deepEqual(accepted.head.terminal, {
    state: 'failed',
    canceled: true,
    errorCode: 'ERR_ABORTED',
    responseReceivedBeforeTerminal: true,
  });
  for (const failure of [
    { canceled: false, errorText: 'net::ERR_ABORTED' },
    { canceled: true, errorText: 'net::ERR_CONNECTION_RESET private@example.com' },
    { canceled: true },
  ])
    assert.equal(observe(failure).head.observed, false);
  for (const setup of [{ extra: false }, { duplicate: true }, { status: 503 }, { initiator: 'other' }])
    assert.equal(observe({ canceled: true, errorText: 'net::ERR_ABORTED' }, setup).head.observed, false);
  const tracker = createHeaderPairTracker(targetOrigin, 'x-content-type-options');
  tracker.event('Network.loadingFailed', { requestId: 'head', canceled: true, errorText: 'net::ERR_ABORTED' });
  wireEvent(tracker, { id: 'head', method: 'HEAD', type: 'Fetch', finished: false });
  assert.equal(
    tracker.value({
      mode: 'control',
      scope: 'same-origin',
      topFrameId: 'private-top-frame',
      naturalHeadObserved: true,
      headStatus: 200,
    }).head.observed,
    false,
  );
  for (const fault of ['no-response', 'no-wire', 'wrong-wire-id', 'redirect', 'get-aborted', 'duplicate-terminal']) {
    const candidate = createHeaderPairTracker(targetOrigin, 'x-content-type-options');
    const send = candidate.event;
    candidate.event = (event, params) => {
      if (fault === 'no-response' && event === 'Network.responseReceived') return;
      if (fault === 'no-wire' && event === 'Network.responseReceivedExtraInfo') return;
      if (fault === 'wrong-wire-id' && event === 'Network.responseReceivedExtraInfo')
        params = { ...params, requestId: 'unrelated' };
      if (fault === 'redirect' && event === 'Network.requestWillBeSent') params = { ...params, redirectResponse: {} };
      send(event, params);
    };
    wireEvent(candidate, {
      id: 'head',
      method: fault === 'get-aborted' ? 'GET' : 'HEAD',
      type: fault === 'get-aborted' ? 'Document' : 'Fetch',
      finished: false,
    });
    candidate.event('Network.loadingFailed', { requestId: 'head', canceled: true, errorText: 'net::ERR_ABORTED' });
    if (fault === 'duplicate-terminal') candidate.event('Network.loadingFinished', { requestId: 'head' });
    const facts = candidate.value({
      mode: 'control',
      scope: 'same-origin',
      topFrameId: 'private-top-frame',
      naturalHeadObserved: true,
      documentStatus: 200,
      headStatus: 200,
    });
    assert.equal((fault === 'get-aborted' ? facts.document : facts.head).observed, false, fault);
  }
  assert.doesNotMatch(
    JSON.stringify(observe({ canceled: true, errorText: 'private@example.com secret' })),
    /private@|secret/,
  );
});

test('DIP aggregates distinguish completion from HTTP transport success and unknown status', () => {
  assert.deepEqual(
    aggregateDipOutcomes([
      { approvedDip: true, method: 'POST', terminal: 'finished', status: 204 },
      { approvedDip: true, method: 'POST', terminal: 'finished', status: 503 },
      { approvedDip: true, method: 'POST', terminal: 'finished', status: null },
      { approvedDip: true, method: 'POST', terminal: 'failed', status: 200 },
      { approvedDip: false, method: 'POST', terminal: 'finished', status: 200 },
      { approvedDip: true, method: 'OPTIONS', terminal: 'finished', status: 200 },
    ]),
    { observed: 4, finished: 3, failed: 1, http2xx: 2, httpNon2xx: 1, statusUnknown: 1 },
  );
});

function pairAdapter({
  dipStatus = 204,
  dipFinished = true,
  duplicateWire = false,
  failMethod,
  abortController,
  captureFailure = false,
  cancelOnHead = false,
  headProvenance = true,
  headFailure = null,
  naturalHeads = 0,
  loaderUrl = `${targetOrigin.origin}/__imp_apg__/js/test.js`,
} = {}) {
  const calls = [],
    contexts = [];
  let active = null;
  const browser = {
    async newContext() {
      const contextNumber = contexts.length;
      const session = new EventEmitter();
      let sequence = 0;
      session.send = async (method, args) => {
        calls.push({ contextNumber, method, args });
        if (method === failMethod) throw new Error('private@example.com token=secret');
        if (method === 'Page.getFrameTree') return { frameTree: { frame: { id: 'private-top-frame' } } };
        if (method === 'Fetch.failRequest') active.get(args.requestId)?.done();
        if (method === 'Fetch.continueRequest') {
          const request = active.get(args.requestId);
          const selector = args.headers.find(({ name }) => name.toLowerCase() === 'x-csd-page-tamper')?.value;
          const headers = { ...HEADER_VALUES };
          if (selector) delete headers[selector];
          const status = request.dip ? dipStatus : 200;
          const emit = (name, params) => session.emit(name, params);
          emit('Network.requestWillBeSentExtraInfo', {
            requestId: args.requestId,
            headers: Object.fromEntries(args.headers.map(({ name, value }) => [name, value])),
          });
          emit('Network.responseReceivedExtraInfo', { requestId: args.requestId, statusCode: status, headers });
          emit('Network.responseReceived', {
            requestId: args.requestId,
            hasExtraInfo: true,
            response: { url: request.url, status, headers },
          });
          if (duplicateWire && request.type === 'Document')
            emit('Network.responseReceivedExtraInfo', { requestId: args.requestId, statusCode: status, headers });
          if (request.method === 'HEAD' && headFailure)
            emit('Network.loadingFailed', { requestId: args.requestId, ...headFailure });
          else if (!request.dip || dipFinished) emit('Network.loadingFinished', { requestId: args.requestId });
          request.done();
        }
        return {};
      };
      session.detach = async () => {
        calls.push({ contextNumber, method: 'detach' });
        if (failMethod === 'detach') throw new Error('secret');
      };
      const page = new EventEmitter();
      page.mainFrame = () => page;
      page.url = () => paymentUrl;
      active = new Map();
      const request = async (url, method, type, dip = false) => {
        const id = `private-${contextNumber}-${sequence++}`;
        await new Promise((done) => {
          active.set(id, { url, method, type, dip, done });
          session.emit('Network.requestWillBeSent', {
            requestId: id,
            request: { url, method },
            type,
            frameId: 'private-top-frame',
            initiator: { type: headProvenance ? 'script' : 'other' },
          });
          if (headProvenance || method !== 'HEAD')
            page.emit('request', { url: () => url, method: () => method, frame: () => page });
          session.emit('Fetch.requestPaused', {
            requestId: id,
            resourceType: type,
            request: { url, method, headers: { 'x-CsD-Page-Tamper': 'untrusted', Accept: 'text/html' } },
          });
        });
      };
      page.goto = async () => {
        await request(paymentUrl, 'GET', 'Document');
        await request(loaderUrl, 'GET', 'Script');
        for (let i = 0; i < naturalHeads; i++) await request(paymentUrl, 'HEAD', 'Fetch');
        await request('https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip', 'POST', 'Fetch', true);
        return { status: () => 200, request: () => ({ redirectedFrom: () => null }) };
      };
      page.evaluate = async (fn) => {
        if (String(fn).includes("method: 'HEAD'")) {
          await request(paymentUrl, 'HEAD', 'Fetch');
          if (cancelOnHead) abortController.abort();
          return { status: 200, exactUrl: true };
        }
        return { paymentFieldsEmpty: true, instrumentationPresent: true };
      };
      const context = {
        newPage: async () => page,
        newCDPSession: async () => session,
        close: async () => {
          calls.push({ contextNumber, method: 'close' });
          if (failMethod === 'close') throw new Error('secret');
        },
      };
      contexts.push(context);
      return context;
    },
  };
  return { browser, contexts, calls, capture: async () => ({ status: captureFailure ? 'failed' : 'captured' }) };
}

test('approved worker trace consumes two distinct canceled HEADs and approved crossorigin loader', async () => {
  for (const [scenario, selector] of Object.entries(HEADER_SCENARIO_SELECTORS))
    for (const scope of ['same-origin', 'document']) {
    const adapter = pairAdapter({
      naturalHeads: 1,
      loaderUrl: 'https://us.gimp.zeronaught.com/__imp_apg__/js/volt-f5_sales_demo_rljyvvmw_client_side_defense-04ba724f.js',
      headFailure: { canceled: true, errorText: 'net::ERR_ABORTED' },
    });
    const pair = await runHeaderPair({ ...adapter, target: targetOrigin, selector, scope, operationTimeoutMs: 500 });
    assert.equal(pair.result, 'passed', JSON.stringify(pair));
    for (const phase of [pair.control, pair.mutation]) {
      assert.equal(phase.head.observed, true);
      assert.equal(phase.sensor.finishedHttp2xx, 1);
      assert.equal(phase.selectorRequests.observed, scope === 'document' ? 1 : 3);
      assert.equal(phase.selectorRequests[phase.mode === 'control' ? 'stripped' : 'injected'], scope === 'document' ? 1 : 3);
      assert.equal(phase.head.headers[selector].present, scope === 'document' || phase.mode === 'control');
    }
    assert.equal(projectHeaderPair(pair, scenario).result, 'passed');
  }
});

test('every extra eligible GET and distinct HEAD must prove wire, selector, headers and terminal', () => {
  for (const mode of ['control', 'mutation']) {
    for (const method of ['GET', 'HEAD']) {
      for (const fault of ['none', 'missing-wire', 'missing-request-wire', 'wrong-selector', 'headers', 'duplicate-header', 'raw-header', 'pending', 'non2xx', 'unknown', 'other', 'null', 'wrong-frame', 'duplicate-id']) {
        const selector = 'cache-control';
        const headers = { ...HEADER_VALUES };
        if (mode === 'mutation') delete headers[selector];
        const tracker = createHeaderPairTracker(targetOrigin, selector);
        const options = { selector: mode === 'mutation' ? selector : null, headers };
        wireEvent(tracker, { ...options, initiator: 'other' });
        wireEvent(tracker, { ...options, id: 'head', method: 'HEAD', type: 'Fetch' });
        const send = tracker.event;
        tracker.event = (event, params) => {
          if (params.requestId === 'extra') {
            if (fault === 'missing-wire' && event === 'Network.responseReceivedExtraInfo') return;
            if (fault === 'missing-request-wire' && event === 'Network.requestWillBeSentExtraInfo') return;
            if (fault === 'wrong-frame' && event === 'Network.requestWillBeSent') params = { ...params, frameId: 'other-frame' };
          }
          send(event, params);
        };
        const extra = {
          ...options, id: 'extra', method, type: 'Fetch',
          selector: fault === 'wrong-selector' ? 'x-frame-options' : options.selector,
          headers: fault === 'headers' ? {} : fault === 'duplicate-header' ? { ...headers, 'X-Frame-Options': 'DENY' } : fault === 'raw-header' ? { ...headers, 'x-frame-options': 'DENY\nDENY' } : headers,
          finished: fault !== 'pending', status: fault === 'non2xx' ? 503 : fault === 'unknown' ? null : 200,
          initiator: ['other', 'null'].includes(fault) ? (fault === 'null' ? null : 'other') : 'script',
        };
        wireEvent(tracker, extra);
        if (fault === 'duplicate-id') wireEvent(tracker, extra);
        const facts = tracker.value({ mode, scope: 'same-origin', topFrameId: 'private-top-frame', naturalHeadObserved: true, documentStatus: 200, headStatus: 200 });
        const fails = fault !== 'none' && (method === 'HEAD' || !['other', 'null', 'wrong-frame'].includes(fault));
        assert.equal(facts.invalid, fails, `${mode} ${method} ${fault}`);
        if (method === 'HEAD') assert.equal(facts.head.observed, !fails, `${mode} ${fault}`);
        assert.equal(facts.selectorRequests.observed, 3);
      }
    }
  }
});

test('document scope consumes every canonical HEAD even when only navigation is selector eligible', () => {
  for (const fault of ['none', 'headers', 'selector', 'unknown', 'other', 'null', 'frame']) {
    const tracker = createHeaderPairTracker(targetOrigin, 'cache-control');
    wireEvent(tracker, { selector: 'cache-control', headers: { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' } });
    wireEvent(tracker, { id: 'head', method: 'HEAD', type: 'Fetch' });
    const send = tracker.event;
    tracker.event = (event, params) => send(event, fault === 'frame' && event === 'Network.requestWillBeSent' ? { ...params, frameId: 'other' } : params);
    wireEvent(tracker, {
      id: 'extra', method: 'HEAD', type: 'Fetch',
      headers: fault === 'headers' ? {} : HEADER_VALUES,
      selector: fault === 'selector' ? 'cache-control' : null,
      initiator: fault === 'null' ? null : ['unknown', 'other'].includes(fault) ? fault : 'script',
    });
    const facts = tracker.value({ mode: 'mutation', scope: 'document', topFrameId: 'private-top-frame', naturalHeadObserved: true, documentStatus: 200, headStatus: 200 });
    assert.equal(facts.selectorRequests.observed, 1);
    assert.equal(facts.head.observed, fault === 'none', fault);
    assert.equal(facts.invalid, fault !== 'none', fault);
  }
});

test('loader evidence requires known wire headers, no selector and finished 2xx', () => {
  for (const setup of [{}, { status: 503 }, { status: null }, { extra: false }, { duplicate: true }, { finished: false }, { selector: 'cache-control' }]) {
    const tracker = createHeaderPairTracker(targetOrigin, 'cache-control');
    wireEvent(tracker, { id: 'loader', type: 'Script', url: 'https://us.gimp.zeronaught.com/__imp_apg__/js/fixture.js', ...setup });
    assert.equal(tracker.value().sensor.finishedHttp2xx, Object.keys(setup).length ? 0 : 1);
  }
});

test('loader routing rejects unknown hosts, DIP and non-anchored paths', async () => {
  for (const loaderUrl of [
    'https://unknown.example/__imp_apg__/js/test.js',
    'https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip',
    `${targetOrigin.origin}/other/__imp_apg__/js/test.js`,
    `${targetOrigin.origin}/__imp_apg__/js/nested/test.js`,
    `${targetOrigin.origin}/__imp_apg__/js/test`,
  ]) {
    const pair = await runHeaderPair({ ...pairAdapter({ loaderUrl }), target: targetOrigin, selector: 'cache-control', operationTimeoutMs: 20 });
    assert.equal(pair.result, 'failed', loaderUrl);
    assert.equal(pair.control.sensor.observed, 0, loaderUrl);
  }
});

test('matched mock pairs observe each frozen omission, natural HEAD, fresh contexts and stripped collectors', async () => {
  for (const [scenario, selector] of Object.entries(HEADER_SCENARIO_SELECTORS)) {
    const adapter = pairAdapter();
    const pair = await runHeaderPair({ ...adapter, target: targetOrigin, selector, operationTimeoutMs: 500 });
    assert.equal(pair.result, 'passed', JSON.stringify(pair));
    assert.equal(adapter.contexts.length, 2);
    assert.deepEqual(Object.keys(projectHeaderPair(pair, scenario)), [
      'selector',
      'scope',
      'pairStartedAt',
      'pairCompletedAt',
      'result',
    ]);
    assert.equal(projectHeaderPair(pair, scenario).pairStartedAt, Date.parse(pair.pairStartedAt));
    for (const phase of [pair.control, pair.mutation]) {
      assert.equal(phase.screenshots.length, 6);
      assert.equal(phase.telemetry.http2xx, 1);
      assert.equal(phase.excludedCollectorOverrideCount, 0);
      assert.equal(phase.document.headers[selector].present, phase.mode === 'control');
      assert.equal(phase.head.headers[selector].present, phase.mode === 'control');
      assert.equal(phase.cleanup.contextClosed, true);
    }
    const resumes = adapter.calls.filter(({ method }) => method === 'Fetch.continueRequest');
    assert.equal(resumes.length, 8);
    assert.equal(resumes.filter(({ args }) => args.headers.some(({ name }) => name === 'X-CSD-Page-Tamper')).length, 2);
    for (const call of resumes) assert.ok(call.args.headers.some(({ name }) => name === 'Accept'));
    assert.doesNotMatch(JSON.stringify(pair), /private-|untrusted|nosniff|no-store|DENY|secret|@/);
    assert.throws(() => projectHeaderPair({ ...pair, rawHeaders: {} }, scenario), /HEADER_PAIR_INVALID/);
    const corrupt = structuredClone(pair);
    corrupt.control.telemetry.statusUnknown = 1;
    assert.throws(() => projectHeaderPair(corrupt, scenario), /HEADER_PAIR_INVALID/);
  }
});

test('paired canceled HEADs retain terminal provenance and canonical receipt validation', async () => {
  const adapter = pairAdapter({ headFailure: { canceled: true, errorText: 'net::ERR_ABORTED' } });
  const pair = await runHeaderPair({
    ...adapter,
    target: targetOrigin,
    selector: 'cache-control',
    operationTimeoutMs: 500,
  });
  assert.equal(pair.result, 'passed');
  assert.equal(projectHeaderPair(pair, 'header-omit-cache-control').result, 'passed');
  for (const phase of [pair.control, pair.mutation]) {
    assert.equal(phase.head.terminal.state, 'failed');
    assert.equal(phase.head.terminal.errorCode, 'ERR_ABORTED');
  }
  for (const mutate of [
    (p) => {
      p.control.head.terminal.canceled = false;
    },
    (p) => {
      p.control.head.terminal.errorCode = 'OTHER';
    },
    (p) => {
      p.control.head.terminal.responseReceivedBeforeTerminal = false;
    },
    (p) => {
      p.control.head.terminal.rawError = 'private';
    },
    (p) => {
      delete p.control.head.terminal;
    },
  ]) {
    const corrupt = structuredClone(pair);
    mutate(corrupt);
    assert.throws(() => projectHeaderPair(corrupt, 'header-omit-cache-control'), /HEADER_PAIR_INVALID/);
  }
});

test('document-only pair leaves natural HEAD canonical without widening request scope', async () => {
  const adapter = pairAdapter();
  const pair = await runHeaderPair({
    ...adapter,
    target: targetOrigin,
    selector: 'x-frame-options',
    scope: 'document',
    operationTimeoutMs: 500,
  });
  assert.equal(pair.result, 'passed');
  assert.equal(pair.mutation.document.headers['x-frame-options'].present, false);
  assert.equal(pair.mutation.head.headers['x-frame-options'].present, true);
});

test('unknown/non2xx/pending DIP, ambiguous wire, missing HEAD provenance and failed screenshot fail closed', async () => {
  for (const options of [
    { dipStatus: null },
    { dipStatus: 503 },
    { dipFinished: false },
    { duplicateWire: true },
    { headProvenance: false },
    { captureFailure: true },
  ]) {
    const adapter = pairAdapter(options);
    const pair = await runHeaderPair({
      ...adapter,
      target: targetOrigin,
      selector: 'cache-control',
      operationTimeoutMs: 35,
    });
    assert.equal(pair.result, 'failed', JSON.stringify(options));
    assert.equal(adapter.contexts.length, 1);
    assert.equal(pair.control.cleanup.contextClosed, true);
    assert.equal(pair.control.cleanup.sessionDetached, true);
    assert.equal(pair.control.cleanup.fetchDisabled, true);
  }
});

test('failed setup/disable/detach/context cleanup and cancellation remain observable without raw diagnostics', async () => {
  for (const failMethod of [
    'Network.enable',
    'Fetch.enable',
    'Fetch.continueRequest',
    'Fetch.disable',
    'detach',
    'close',
  ]) {
    const adapter = pairAdapter({ failMethod });
    const pair = await runHeaderPair({
      ...adapter,
      target: targetOrigin,
      selector: 'cache-control',
      operationTimeoutMs: 100,
    });
    assert.equal(pair.result, 'failed', failMethod);
    assert.equal(adapter.contexts.length, 1);
    assert.ok(adapter.calls.some(({ method }) => method === 'detach'));
    assert.ok(adapter.calls.some(({ method }) => method === 'close'));
    assert.doesNotMatch(JSON.stringify(pair), /secret|private@example/);
  }
  const controller = new AbortController();
  const adapter = pairAdapter({ abortController: controller, cancelOnHead: true });
  const pair = await runHeaderPair({
    ...adapter,
    target: targetOrigin,
    selector: 'cache-control',
    signal: controller.signal,
    operationTimeoutMs: 100,
  });
  assert.equal(pair.result, 'failed');
  assert.equal(pair.pairCompletedAt, null);
  assert.equal(pair.control.cleanup.contextClosed, true);
  assert.equal(pair.control.cleanup.fetchDisabled, true);
  assert.equal(projectHeaderPair(pair, 'header-omit-cache-control').pairCompletedAt, null);
  assert.equal(projectHeaderPair(null, expectedNames[0]), null);
  assert.throws(() => projectHeaderPair(pair, expectedNames[0]), /HEADER_PAIR_INVALID/);
  assert.throws(() => projectHeaderPair(pair, 'header-omit-x-frame-options'), /HEADER_PAIR_INVALID/);
});

test('pre-cancelled pair acquires no browser resources and projects only actual start facts', async () => {
  const controller = new AbortController();
  controller.abort();
  const adapter = pairAdapter();
  const pair = await runHeaderPair({
    ...adapter,
    target: targetOrigin,
    selector: 'cache-control',
    signal: controller.signal,
  });
  assert.equal(adapter.contexts.length, 0);
  assert.equal(pair.result, 'failed');
  assert.equal(pair.control, null);
  assert.equal(pair.mutation, null);
  assert.equal(projectHeaderPair(pair, 'header-omit-cache-control').pairCompletedAt, null);
});

test('pair API rejects arbitrary selectors, URLs and scopes before browser acquisition', async () => {
  for (const override of [
    { selector: 'content-security-policy' },
    { scope: 'all-assets' },
    { target: new URL('https://unapproved.example.com') },
    { target: new URL(paymentUrl) },
    { target: new URL(`${targetOrigin.origin}/?query=private`) },
  ]) {
    const adapter = pairAdapter();
    await assert.rejects(
      runHeaderPair({ ...adapter, target: targetOrigin, selector: 'cache-control', ...override }),
      /HEADER_PAIR_INVALID/,
    );
    assert.equal(adapter.contexts.length, 0);
  }
});

test('projection rejects backwards timestamps, fabricated counters and raw nested fields', async () => {
  const adapter = pairAdapter();
  const pair = await runHeaderPair({
    ...adapter,
    target: targetOrigin,
    selector: 'cache-control',
    operationTimeoutMs: 500,
  });
  assert.equal(pair.result, 'passed');
  for (const corrupt of [
    { ...pair, pairCompletedAt: '1970-01-01T00:00:00.000Z' },
    { ...pair, pairStartedAt: '2026-02-30T00:00:00.000Z' },
    { ...pair, scope: 'all-assets' },
  ])
    assert.throws(() => projectHeaderPair(corrupt, 'header-omit-cache-control'), /HEADER_PAIR_INVALID/);
  for (const mutate of [
    (p) => {
      p.control.telemetry.rawBody = 'private';
    },
    (p) => {
      p.control.telemetry.observed = 2;
    },
    (p) => {
      p.control.document.headers['cache-control'].rawValue = 'private';
    },
    (p) => {
      p.control.selectorRequests.stripped = 0;
    },
    (p) => {
      p.control.cleanup.errors = ['private error'];
    },
    (p) => {
      p.mutation.startedAt = '1970-01-01T00:00:00.000Z';
    },
  ]) {
    const corrupt = structuredClone(pair);
    mutate(corrupt);
    assert.throws(() => projectHeaderPair(corrupt, 'header-omit-cache-control'), /HEADER_PAIR_INVALID/);
  }
});

test('bounded operation cancelled before dispatch never starts an adapter side effect', async () => {
  const controller = new AbortController();
  let sideEffects = 0;
  const pending = boundedOperation(
    () => {
      sideEffects++;
    },
    100,
    controller.signal,
  );
  controller.abort();
  await assert.rejects(pending, /RUN_INTERRUPTED/);
  assert.equal(sideEffects, 0);
});
