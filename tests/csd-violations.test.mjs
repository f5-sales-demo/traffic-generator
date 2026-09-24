import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  buildReceipt,
  pageHelpers,
  runSuite,
  sanitizeUrl,
  validateAwsRuntime,
  validateTarget,
} from '../suites/csd-violations/run.mjs';
import {
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
  assert.deepEqual(SCENARIO_NAMES, expectedNames);
  assert.equal(new Set(SCENARIO_NAMES).size, 11);
  assert.ok(SCENARIOS.every((scenario) => scenario.steps.every((step) => step.assertions?.length > 0)));
  assert.ok(SCENARIOS.every((scenario) => scenario.steps.at(-1)?.op === 'cleanup'));
  assert.ok(
    SCENARIOS.every((scenario) => {
      const fields = scenario.steps.at(-1).assertions.map(({ field }) => field);
      return ['artifactCount', 'controlValueCount', 'sensitiveValueCount', 'timerCount', 'listenerAttached'].every(
        (field) => fields.includes(field),
      );
    }),
  );
  assert.deepEqual(
    Object.fromEntries(SCENARIOS.map(({ name, steps }) => [name, steps.find(({ op }) => op === 'navigate')?.route])),
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
  const sanitized = sanitizeUrl('https://example.invalid/path?email=a%40b.invalid&safe=yes&token=secret#fragment');
  assert.match(sanitized, /email=%5BREDACTED%5D/);
  assert.match(sanitized, /token=%5BREDACTED%5D/);
  assert.match(sanitized, /safe=yes/);
  assert.doesNotMatch(sanitized, /fragment|secret|a%40b/);
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
  assert.equal(receipt.schemaVersion, 2);
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
  assert.match(source, /controlValueCount/);
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
    assert.equal(globalThis.window.__csdSim.cleanupPage().timerCount, 0);
  } finally {
    globalThis.window = originalWindow;
    globalThis.document = originalDocument;
    globalThis.fetch = originalFetch;
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
        controlValueCount: 0,
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

test('serialized receipt stores bounded errors while stderr retains local diagnostics', async () => {
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
    assert.ok(stderr.some((message) => message.includes(secretError)));
  } finally {
    console.error = originalConsoleError;
    await rm(outputDirectory, { recursive: true, force: true });
  }
});

test('shell wrapper uses an immutable retryable upload commit protocol', async () => {
  const source = await readFile(new URL('../suites/csd-violations/run.sh', import.meta.url), 'utf8');
  assert.match(source, /RESULTS_ROOT="\$\{RESULTS_ROOT:-\/opt\/traffic-generator\/runtime\/results\}"/);
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
  assert.match(source, /source "\$RUNTIME_ENV"/);
  assert.match(source, /CHROME_PATH=\/opt\/chrome\/chrome/);
  assert.doesNotMatch(source, /google-chrome|chromium-browser|command -v "\$candidate"/);
  assert.match(source, /AWS_CLI_BIN="\$\{AWS_CLI_BIN:\?AWS_CLI_BIN is required\}"/);
  assert.match(source, /AWS_CLI_VERSION="\$\{AWS_CLI_VERSION:\?AWS_CLI_VERSION is required\}"/);
  assert.match(source, /"\$AWS_CLI_BIN" --version 2>&1/);
  assert.match(source, /"\$AWS_CLI_BIN" s3api head-object/);
  assert.match(source, /"\$AWS_CLI_BIN" s3 cp/);
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
  const stepCount = SCENARIOS.reduce((count, scenario) => count + scenario.steps.length, 0);
  const cleanupCount = SCENARIOS.reduce(
    (count, scenario) => count + scenario.steps.filter(({ op }) => op === 'cleanup').length,
    0,
  );
  assert.equal(cleanupCount, SCENARIOS.length);
  assert.equal(stepCount, 45);
  assert.equal(stepCount + SCENARIOS.length, 56);
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
