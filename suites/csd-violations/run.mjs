#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { SCENARIOS, SUITE_MANIFEST } from './scenarios.mjs';

const EXPECTED_HOST = 'client-side-defense.f5-sales-demo.com';
const SENSOR_RE = /\/__imp_apg__\/js\//;
const DIP_RE = /\/__imp_apg__\/api\/dip/;
const REDACTED_URL_KEYS = new Set(['email', 'password', 'token', 'key', 'card', 'cookie', 'authorization']);

export function validateTarget(rawTarget, expectedHost = EXPECTED_HOST) {
  const target = new URL(rawTarget);
  if (target.protocol !== 'https:' || target.hostname !== expectedHost || target.username || target.password)
    throw new Error(`TARGET_URL must be https://${expectedHost}`);
  return target;
}

export function sanitizeUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    for (const key of [...url.searchParams.keys()])
      if (REDACTED_URL_KEYS.has(key.toLowerCase())) url.searchParams.set(key, '[REDACTED]');
    url.hash = '';
    return url.toString();
  } catch {
    return '[invalid-url]';
  }
}

const PERSISTED_ERRORS = Object.freeze({
  screenshot: {
    code: 'SCREENSHOT_CAPTURE_FAILED',
    category: 'evidence',
    message: 'Screenshot capture failed.',
  },
  step: {
    code: 'STEP_EXECUTION_FAILED',
    category: 'scenario',
    message: 'Scenario step execution failed.',
  },
  pageCleanup: {
    code: 'PAGE_CLEANUP_FAILED',
    category: 'cleanup',
    message: 'Page cleanup failed.',
  },
  contextCleanup: {
    code: 'CONTEXT_CLEANUP_FAILED',
    category: 'cleanup',
    message: 'Browser context cleanup failed.',
  },
  browserCleanup: {
    code: 'BROWSER_CLEANUP_FAILED',
    category: 'cleanup',
    message: 'Browser cleanup failed.',
  },
});

export function persistedError(kind) {
  const failure = PERSISTED_ERRORS[kind];
  if (!failure) throw new Error('unsupported persisted error category');
  return {
    errorCode: failure.code,
    errorCategory: failure.category,
    errorMessage: failure.message,
  };
}

function reportLocalError(context, error) {
  console.error(`${context}: ${String(error?.message || error)}`);
}

function screenshotFailureCount(scenario) {
  return (
    scenario.steps.filter((step) => step.screenshot?.status === 'failed').length +
    (scenario.finalScreenshot?.status === 'failed' ? 1 : 0)
  );
}

export function buildReceipt({ runId, target, startedAt, completedAt, scenarios, cleanup, runtime = {}, objectKey }) {
  const counts = scenarios.reduce(
    (result, scenario) => {
      result.total += 1;
      result[scenario.status] += 1;
      result.steps += scenario.steps.length;
      result.screenshotFailures += screenshotFailureCount(scenario);
      result.assertionFailures += scenario.steps.filter((step) => step.assertions?.status === 'failed').length;
      return result;
    },
    {
      total: 0,
      passed: 0,
      failed: 0,
      steps: 0,
      screenshotFailures: 0,
      assertionFailures: 0,
    },
  );
  return {
    schemaVersion: 2,
    manifest: {
      schemaVersion: SUITE_MANIFEST.schemaVersion,
      name: SUITE_MANIFEST.name,
      displayName: SUITE_MANIFEST.displayName,
      category: SUITE_MANIFEST.category,
      preconditions: SUITE_MANIFEST.preconditions,
      syntheticDataPolicy: SUITE_MANIFEST.syntheticDataPolicy,
      immediateEvidence: SUITE_MANIFEST.immediateEvidence,
      cleanup: SUITE_MANIFEST.cleanup,
      destinations: SUITE_MANIFEST.destinations,
      screenshotRequirement: SUITE_MANIFEST.screenshotRequirement,
      claimBoundary: SUITE_MANIFEST.claimBoundary,
    },
    runId,
    objectKey,
    target: { protocol: target.protocol, host: target.hostname },
    startedAt,
    completedAt,
    runtime,
    counts,
    discarded: false,
    discardReasons: [],
    scenarios,
    cleanup,
    caveat: SUITE_MANIFEST.claimBoundary,
  };
}

function networkOutcome(request) {
  const parsed = new URL(request.url());
  return {
    method: request.method(),
    resourceType: request.resourceType(),
    origin: `${parsed.protocol}//${parsed.host}`,
    path: parsed.pathname,
    terminal: 'pending',
  };
}

function safeFilename(value) {
  return value
    .replace(/[^a-z0-9-]+/gi, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase();
}

async function maskInputs(page) {
  return page.evaluate(() => {
    const nativeValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    const nativeTextAreaSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
    const nativeSelectSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
    let cleared = 0;
    for (const control of document.querySelectorAll('input, textarea, select')) {
      if ('value' in control && control.value) cleared += 1;
      const setter =
        control instanceof HTMLInputElement
          ? nativeValueSetter
          : control instanceof HTMLTextAreaElement
            ? nativeTextAreaSetter
            : nativeSelectSetter;
      setter?.call(control, '');
      control.removeAttribute('value');
      control.removeAttribute('placeholder');
      control.setAttribute('data-csd-masked', 'true');
      control.dispatchEvent(new Event('input', { bubbles: true }));
      control.dispatchEvent(new Event('change', { bubbles: true }));
    }
    for (const node of document.querySelectorAll('[data-csd-sensitive]')) {
      node.textContent = 'Synthetic masked display';
      node.setAttribute('data-csd-masked', 'true');
    }
    return cleared;
  });
}

async function captureScreenshot(
  page,
  outputDirectory,
  runId,
  scenarioIndex,
  scenarioName,
  stepIndex,
  stepName,
  assertionStatus,
) {
  const filename = `${String(scenarioIndex + 1).padStart(2, '0')}-${safeFilename(scenarioName)}-${String(stepIndex + 1).padStart(2, '0')}-${safeFilename(stepName)}.png`;
  const scenarioDirectory = resolve(outputDirectory, safeFilename(scenarioName));
  const path = resolve(scenarioDirectory, filename);
  const temporaryPath = `${path}.tmp-${process.pid}`;
  const objectKey = `runs/${runId}/${safeFilename(scenarioName)}/${filename}`;
  const startedAt = new Date().toISOString();
  try {
    await mkdir(scenarioDirectory, { recursive: true });
    const maskedInputCount = await maskInputs(page);
    await page.screenshot({ path: temporaryPath, type: 'png', fullPage: true });
    await rename(temporaryPath, path);
    const sha256 = createHash('sha256')
      .update(await readFile(path))
      .digest('hex');
    return {
      status: 'captured',
      captureStatus: 'captured',
      assertionStatus,
      uploadStatus: 'pending',
      startedAt,
      completedAt: new Date().toISOString(),
      path: filename,
      localPath: path,
      objectKey,
      sha256,
      maskedInputCount,
    };
  } catch (error) {
    reportLocalError('screenshot capture failed', error);
    await rm(temporaryPath, { force: true }).catch(() => {});
    return {
      status: 'failed',
      captureStatus: 'failed',
      assertionStatus,
      uploadStatus: 'not-attempted',
      startedAt,
      completedAt: new Date().toISOString(),
      path: filename,
      localPath: path,
      objectKey,
      sha256: null,
      maskedInputCount: 0,
      ...persistedError('screenshot'),
    };
  }
}

function valueAt(source, field) {
  return field.split('.').reduce((value, key) => value?.[key], source);
}

function checkAssertion(actual, contract) {
  if (actual === undefined || actual === null) return false;
  if (contract.operator === 'eq') return actual === contract.value;
  if (contract.operator === 'gt') return typeof actual === 'number' && actual > contract.value;
  if (contract.operator === 'gte') return typeof actual === 'number' && actual >= contract.value;
  if (contract.operator === 'lt') return typeof actual === 'number' && actual < contract.value;
  if (contract.operator === 'oneOf') return contract.value.includes(actual);
  throw new Error(`unsupported assertion operator: ${contract.operator}`);
}

function assertEvidence(step, stepResult) {
  const contracts = step.assertions ?? [];
  if (contracts.length === 0) throw new Error(`step ${step.name} has no assertion contract`);
  const checks = contracts.map((contract) => {
    const actual = valueAt(stepResult, contract.field) ?? valueAt(stepResult.evidence, contract.field);
    return { ...contract, actual, passed: checkAssertion(actual, contract) };
  });
  return {
    status: checks.every(({ passed }) => passed) ? 'passed' : 'failed',
    checks,
  };
}

export function pageHelpers({ terminalTimeoutMs = 8_000, runId = null, scenarioName = null } = {}) {
  const SCRIPT_URLS = {
    jsdelivr: 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js',
    esm: 'https://esm.sh/moment@2.30.1',
    unpkg: 'https://unpkg.com/underscore@1.13.7/underscore-min.js',
    jspm: 'https://ga.jspm.io/npm:dayjs@1.11.13/dayjs.min.js',
  };
  const tracked = { nodes: new Set(), timers: new Set() };
  const managedContext = { runId, scenarioName };
  const CLEANUP_SETTLE_MS = 250;
  const CLEANUP_POLL_MS = 25;
  const findInput = (kind) => {
    const selectors = {
      email: ['#email', 'input[type="email"]', 'input[name*="email" i]', 'input[autocomplete="username"]'],
      password: ['#password', 'input[type="password"]', 'input[autocomplete="current-password"]'],
    };
    return selectors[kind].map((selector) => document.querySelector(selector)).find(Boolean);
  };
  const beginScenario = (runId, scenarioName) => {
    managedContext.runId = runId;
    managedContext.scenarioName = scenarioName;
    return { initialized: Boolean(runId && scenarioName) };
  };
  const terminalFetch = async (url, body) => {
    const controller = new AbortController();
    let timer;
    const request = fetch(url, {
      method: 'POST',
      mode: 'no-cors',
      keepalive: false,
      headers: { 'content-type': 'text/plain' },
      body: JSON.stringify(body),
      signal: controller.signal,
    }).then(
      () => 'finished',
      () => (controller.signal.aborted ? 'timed-out' : 'failed'),
    );
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve('timed-out');
      }, terminalTimeoutMs);
      tracked.timers.add(timer);
    });
    try {
      return await Promise.race([request, timeout]);
    } finally {
      clearTimeout(timer);
      tracked.timers.delete(timer);
    }
  };
  const injectScript = (src, attributes = {}) =>
    new Promise((resolve) => {
      const script = document.createElement('script');
      script.src = src;
      script.async = true;
      for (const [key, value] of Object.entries(attributes)) script.dataset[key] = value;
      tracked.nodes.add(script);
      const done = (terminal) => {
        clearTimeout(timer);
        tracked.timers.delete(timer);
        resolve(terminal);
      };
      script.onload = () => done('finished');
      script.onerror = () => done('failed');
      const timer = setTimeout(() => done('timed-out'), 8_000);
      tracked.timers.add(timer);
      document.head.appendChild(script);
    });
  const setNativeValue = (control, value) => {
    const prototype =
      control instanceof HTMLInputElement
        ? HTMLInputElement.prototype
        : control instanceof HTMLTextAreaElement
          ? HTMLTextAreaElement.prototype
          : HTMLSelectElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, 'value')?.set?.call(control, value);
  };
  const dispatchValueEvents = (control) => {
    control.dispatchEvent(new Event('input', { bubbles: true }));
    control.dispatchEvent(new Event('change', { bubbles: true }));
    control.dispatchEvent(new Event('blur', { bubbles: false }));
  };
  const syntheticFill = (control, value) => {
    if (!managedContext.runId || !managedContext.scenarioName)
      throw new Error('scenario context must be initialized before synthetic fill');
    setNativeValue(control, value);
    control.setAttribute('data-csd-synthetic', 'true');
    control.setAttribute('data-csd-run', managedContext.runId);
    control.setAttribute('data-csd-scenario', managedContext.scenarioName);
    dispatchValueEvents(control);
  };
  const managedControls = () =>
    [...document.querySelectorAll('[data-csd-synthetic="true"]')].filter(
      (control) =>
        control.getAttribute('data-csd-run') === managedContext.runId &&
        control.getAttribute('data-csd-scenario') === managedContext.scenarioName,
    );
  const setSyntheticFields = (entries) => {
    let setCount = 0;
    for (const [kind, value] of entries) {
      const control = findInput(kind);
      if (!control) continue;
      syntheticFill(control, value);
      setCount += 1;
    }
    return {
      setCount,
      markerCount: managedControls().length,
      syntheticOnly: true,
    };
  };
  const observeFields = (kinds) => ({
    observedFieldCount: kinds.filter((kind) => Boolean(findInput(kind))).length,
  });
  const observeControls = () => ({
    observedControlCount: document.querySelectorAll('input,select,textarea').length,
  });
  const injectReviewedScripts = async () => {
    const results = await Promise.all(
      Object.entries(SCRIPT_URLS).map(async ([name, url]) => [name, await injectScript(url, { csdSimulation: name })]),
    );
    return { candidateCount: results.length, ...Object.fromEntries(results) };
  };
  const counterPost = async (url, counters) => ({
    postedCount: Object.values(counters).reduce((sum, value) => sum + Number(value || 0), 0),
    terminal: await terminalFetch(url, counters),
  });
  const attemptChannels = async () => {
    const fetchPost = await terminalFetch('https://www.httpbin.org/post', {
      observedFieldCount: 2,
    });
    const image = new Image();
    image.alt = 'synthetic evidence';
    image.src = 'https://jsonplaceholder.typicode.com/favicon.ico';
    tracked.nodes.add(image);
    document.body.appendChild(image);
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = SCRIPT_URLS.jsdelivr;
    tracked.nodes.add(link);
    document.head.appendChild(link);
    return {
      channelCount: 3,
      fetchPost,
      imageAttempted: true,
      prefetchAttempted: true,
    };
  };
  const installBanner = () => {
    const banner = document.createElement('div');
    banner.dataset.csdOverlay = 'banner';
    banner.textContent = 'Synthetic CSD simulation';
    banner.style.cssText =
      'position:fixed;inset:20% 20% auto;z-index:2147483647;background:#fff;border:4px solid #c00;padding:2rem';
    tracked.nodes.add(banner);
    document.body.appendChild(banner);
    return { installed: true };
  };
  const sensitiveValueCount = () => {
    const syntheticValue = /synthetic|password|(?:\d[ -]?){12,19}/i;
    const controlValues = [...document.querySelectorAll('input,textarea,select')].map((control) => control.value);
    const sensitiveText = [...document.querySelectorAll('[data-csd-sensitive]')].map((node) => node.textContent);
    return [...controlValues, ...sensitiveText].filter((value) => value && syntheticValue.test(value)).length;
  };
  const cleanupPage = async () => {
    for (const node of tracked.nodes) node.remove();
    tracked.nodes.clear();
    for (const timer of tracked.timers) clearTimeout(timer);
    tracked.timers.clear();
    if (window.__csdKeyListener) document.removeEventListener('keydown', window.__csdKeyListener);
    window.__csdKeyListener = null;
    const deadline = Date.now() + CLEANUP_SETTLE_MS;
    let controls = managedControls();
    do {
      for (const control of controls) {
        setNativeValue(control, '');
        control.removeAttribute('value');
        control.removeAttribute('placeholder');
        dispatchValueEvents(control);
      }
      await new Promise((resolve) => setTimeout(resolve, CLEANUP_POLL_MS));
      controls = managedControls();
    } while (controls.some((control) => control.value) && Date.now() < deadline);
    const managedControlValueCount = controls.filter((control) => control.value).length;
    if (managedControlValueCount === 0)
      for (const control of controls) {
        control.removeAttribute('data-csd-synthetic');
        control.removeAttribute('data-csd-run');
        control.removeAttribute('data-csd-scenario');
      }
    for (const node of document.querySelectorAll('[data-csd-sensitive]')) node.textContent = '';
    return {
      artifactCount: document.querySelectorAll(
        '[data-csd-overlay],[data-csd-simulation],[data-tag-manager="synthetic"],link[rel="prefetch"]',
      ).length,
      managedControlValueCount,
      sensitiveValueCount: sensitiveValueCount(),
      timerCount: tracked.timers.size,
      listenerAttached: Boolean(window.__csdKeyListener),
    };
  };
  window.__csdSim = {
    beginScenario,
    observeFields,
    observeControls,
    setSyntheticLogin: () =>
      setSyntheticFields([
        ['email', 'synthetic-login@example.com'],
        ['password', 'Synthetic-Only-Password-42!'],
      ]),
    setSyntheticRegistration: () => {
      const controls = [...document.querySelectorAll('input,textarea,select')].slice(0, 8);
      let setCount = 0;
      for (const [index, control] of controls.entries()) {
        if (control instanceof HTMLSelectElement) continue;
        syntheticFill(
          control,
          control.type === 'password' ? 'Synthetic-Only-Password-42!' : `synthetic-${index}@example.com`,
        );
        setCount += 1;
      }
      return {
        setCount,
        markerCount: document.querySelectorAll('[data-csd-synthetic="true"]').length,
        syntheticOnly: true,
      };
    },
    counterPost,
    injectReviewedScripts,
    attemptChannels,
    installBanner,
    cleanupPage,
    installPaymentOverlay() {
      const originalFieldCount = document.querySelectorAll('input,select,textarea').length;
      const overlay = document.createElement('div');
      overlay.dataset.csdOverlay = 'payment';
      overlay.style.cssText =
        'position:fixed;inset:15%;z-index:2147483647;background:#fff;border:4px solid #c00;padding:2rem';
      const label = document.createElement('div');
      label.dataset.csdSensitive = 'payment';
      label.textContent = 'Synthetic card •••• •••• •••• ••••';
      overlay.appendChild(label);
      tracked.nodes.add(overlay);
      document.body.appendChild(overlay);
      window.__csdOriginalPaymentFieldCount = originalFieldCount;
      return {
        installed: true,
        maskedDisplayOnly: !overlay.querySelector('input'),
        originalFieldCount,
      };
    },
    async postOriginalPaymentFieldCounter() {
      const originalFieldCount = window.__csdOriginalPaymentFieldCount;
      return counterPost('https://www.httpbin.org/post', {
        originalFieldCount,
      });
    },
    async injectObfuscatedLoader() {
      const encoded = 'aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS9sb2Rhc2hANC4xNy4yMS9sb2Rhc2gubWluLmpz';
      const decoded = atob(encoded);
      return {
        decodedBytes: decoded.length,
        terminal: await injectScript(decoded, {
          csdSimulation: 'obfuscated-loader',
        }),
      };
    },
    async installTagManagerCandidate() {
      const terminal = await injectScript('https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js', {
        tagManager: 'synthetic',
      });
      return { tagged: true, terminal };
    },
    async highVolumeAttempts() {
      const scriptAttempts = [
        ['scriptJsdelivr', SCRIPT_URLS.jsdelivr],
        ['scriptEsm', SCRIPT_URLS.esm],
        ['scriptUnpkg', SCRIPT_URLS.unpkg],
        ['scriptJspm', SCRIPT_URLS.jspm],
        ['scriptChartjs', 'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js'],
      ];
      const outcomes = Object.fromEntries(
        await Promise.all(
          scriptAttempts.map(async ([name, url]) => [name, await injectScript(url, { csdSimulation: 'high-volume' })]),
        ),
      );
      outcomes.postHttpbin = await terminalFetch('https://www.httpbin.org/post', { count: 1 });
      outcomes.postJsonplaceholder = await terminalFetch('https://jsonplaceholder.typicode.com/posts', { count: 1 });
      return {
        attemptCount: 7,
        scriptCount: 5,
        postCount: 2,
        terminalCount: Object.values(outcomes).filter((value) =>
          ['finished', 'blocked', 'failed', 'timed-out'].includes(value),
        ).length,
        outcomes,
      };
    },
    installFormOverlay() {
      const originalFieldCount = document.querySelectorAll('input,select,textarea').length;
      const overlay = document.createElement('form');
      overlay.dataset.csdOverlay = 'login';
      overlay.style.cssText =
        'position:fixed;inset:20%;z-index:2147483647;background:#fff;border:4px solid #c00;padding:2rem';
      overlay.textContent = 'Synthetic login overlay (no values collected)';
      tracked.nodes.add(overlay);
      document.body.appendChild(overlay);
      return {
        originalFieldCount,
        installed: true,
        hasGeometry: overlay.getBoundingClientRect().width > 0,
      };
    },
    async runKeyCounter(count) {
      let eventCount = 0;
      const listener = () => {
        eventCount += 1;
      };
      window.__csdKeyListener = listener;
      document.addEventListener('keydown', listener);
      for (let index = 0; index < count; index += 1)
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'x', bubbles: true }));
      document.removeEventListener('keydown', listener);
      window.__csdKeyListener = null;
      const timer = setTimeout(() => {}, 1);
      clearTimeout(timer);
      return { eventCount, listenerDetached: true, timerCleared: true };
    },
  };
}

export async function validateAwsRuntime(environment = process.env, platform = process.platform) {
  if (environment.CSD_AWS_RUNTIME !== '1') throw new Error('CSD_AWS_RUNTIME=1 is required for real browser execution');
  if (platform !== 'linux') throw new Error(`AWS browser execution requires Linux; detected ${platform}`);
  const sourceCommit = environment.SOURCE_COMMIT;
  if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? '')) throw new Error('SOURCE_COMMIT must be the exact deployed commit');
  const statusPath = environment.CSD_AWS_STATUS_PATH ?? '/opt/traffic-generator/status.json';
  const status = JSON.parse(await readFile(statusPath, 'utf8'));
  const allowedStatuses = environment.CSD_AWS_ALLOW_VERIFYING_STATUS === '1' ? ['verifying'] : ['ready'];
  if (!allowedStatuses.includes(status.status) || status.source_commit !== sourceCommit || status.runtime !== 'aws')
    throw new Error('AWS deployment status is not ready or does not match SOURCE_COMMIT');
  const chromePath = environment.CHROME_PATH ?? '/opt/chrome/chrome';
  if (chromePath !== '/opt/chrome/chrome') throw new Error('CHROME_PATH must be /opt/chrome/chrome');
  const playwrightRoot = environment.CSD_PLAYWRIGHT_ROOT ?? '/opt/traffic-generator/node_modules';
  if (playwrightRoot !== '/opt/traffic-generator/node_modules')
    throw new Error('CSD_PLAYWRIGHT_ROOT must be /opt/traffic-generator/node_modules');
  const playwrightPath = resolve(playwrightRoot, 'playwright-core/package.json');
  await access(chromePath, constants.X_OK);
  await access(playwrightPath, constants.R_OK);
  if (!/^:\d+$/.test(environment.DISPLAY ?? '')) throw new Error('DISPLAY must identify the deployed Xvfb display');
  const displaySocket = `/tmp/.X11-unix/X${environment.DISPLAY.slice(1)}`;
  const socket = await stat(displaySocket);
  if (!socket.isSocket()) throw new Error(`Xvfb display socket is unavailable: ${displaySocket}`);
  const runId = environment.RUN_ID ?? '';
  if (!/^[a-z0-9][a-z0-9-]{0,127}$/.test(runId))
    throw new Error('RUN_ID must contain only lowercase letters, digits, and hyphens');
  const outputDirectory = resolve(environment.CSD_AWS_OUTPUT_DIR ?? '');
  const expectedOutputDirectory = resolve('/opt/traffic-generator/runtime/results', runId);
  if (outputDirectory !== expectedOutputDirectory)
    throw new Error(`CSD_AWS_OUTPUT_DIR must equal ${expectedOutputDirectory}`);
  const runtime = {
    repository: environment.SOURCE_REPOSITORY_URL,
    sourceCommit,
    chromeVersion: environment.CHROME_VERSION ?? status.chrome_version,
    nodeVersion: environment.NODE_VERSION ?? status.node_version,
    amiId: environment.AMI_ID,
    instanceId: environment.INSTANCE_ID ?? status.instance_id,
    region: environment.AWS_REGION,
    manifestVersion: environment.DEPLOYMENT_MANIFEST_VERSION,
    manifestDigest: environment.DEPLOYMENT_MANIFEST_SHA256,
  };
  for (const [field, value] of Object.entries(runtime))
    if (!value) throw new Error(`runtime provenance is missing ${field}`);
  if (
    status.repository !== runtime.repository ||
    status.source_commit !== runtime.sourceCommit ||
    status.ami_id !== runtime.amiId ||
    status.region !== runtime.region ||
    status.manifest?.version !== runtime.manifestVersion ||
    status.manifest?.sha256 !== runtime.manifestDigest
  )
    throw new Error('AWS deployment status provenance does not match the deployed runtime environment');
  return {
    chromePath,
    outputDirectory,
    playwrightPath,
    runId,
    sourceCommit,
    statusPath,
    runtime,
  };
}

export async function runSuite(options = {}) {
  let runtime;
  if (!options.playwright) runtime = await validateAwsRuntime();
  const expectedHost = options.expectedHost ?? EXPECTED_HOST;
  const target = validateTarget(options.targetUrl ?? process.env.TARGET_URL ?? `https://${expectedHost}`, expectedHost);
  const outputDirectory = resolve(
    options.outputDirectory ??
      runtime?.outputDirectory ??
      process.env.RESULTS_DIR ??
      `results/${Date.now()}-csd-violations`,
  );
  const runId = options.runId ?? runtime?.runId ?? process.env.RUN_ID ?? `csd-${Date.now()}-${process.pid}`;
  if (!/^[a-z0-9][a-z0-9-]{0,127}$/.test(runId)) throw new Error('runId contains unsafe path characters');
  const requestedScenario = options.scenario ?? process.env.CSD_SCENARIO;
  const selectedScenarios = requestedScenario ? SCENARIOS.filter(({ name }) => name === requestedScenario) : SCENARIOS;
  if (requestedScenario && selectedScenarios.length !== 1) throw new Error('CSD_SCENARIO is not allowlisted');
  const executablePath = options.executablePath ?? runtime?.chromePath ?? process.env.CHROME_PATH;
  const startedAt = new Date().toISOString();
  await mkdir(outputDirectory, { recursive: true });
  let playwright = options.playwright;
  if (!playwright) {
    const packagePath = runtime.playwrightPath;
    playwright = await import(pathToFileURL(resolve(dirname(packagePath), 'index.mjs')).href);
  }
  const browser = await playwright.chromium.launch({
    executablePath,
    channel: executablePath ? undefined : 'chrome',
    headless: false,
    args: ['--disable-dev-shm-usage'],
  });
  const scenarioResults = [];
  const cleanup = { browser: 'pending', contexts: 0, errors: [] };
  try {
    for (const [scenarioIndex, scenario] of selectedScenarios.entries()) {
      const context = await browser.newContext({
        ignoreHTTPSErrors: options.ignoreHTTPSErrors ?? false,
      });
      cleanup.contexts += 1;
      await context.addInitScript(pageHelpers, { runId, scenarioName: scenario.name });
      const page = await context.newPage();
      const requests = new Map();
      const instrumentation = { sensorRequests: 0, dipRequests: 0 };
      const scenarioResult = {
        name: scenario.name,
        displayName: scenario.displayName,
        category: scenario.category,
        preconditions: scenario.preconditions,
        syntheticDataPolicy: scenario.syntheticDataPolicy,
        immediateEvidence: scenario.immediateEvidence,
        cleanupRequirement: scenario.cleanup,
        destinations: scenario.destinations,
        screenshotRequirement: scenario.screenshotRequirement,
        claimBoundary: scenario.claimBoundary,
        status: 'passed',
        startedAt: new Date().toISOString(),
        steps: [],
        network: [],
        instrumentation,
      };
      page.on('request', (request) => {
        const outcome = networkOutcome(request);
        requests.set(request, outcome);
        if (SENSOR_RE.test(request.url())) instrumentation.sensorRequests += 1;
        if (DIP_RE.test(request.url())) instrumentation.dipRequests += 1;
      });
      page.on('requestfinished', (request) => {
        const outcome = requests.get(request);
        if (outcome) outcome.terminal = 'finished';
      });
      page.on('requestfailed', (request) => {
        const outcome = requests.get(request);
        if (outcome) outcome.terminal = 'blocked';
      });
      try {
        for (const [stepIndex, step] of scenario.steps.entries()) {
          const stepResult = {
            name: step.name,
            operation: step.op,
            startedAt: new Date().toISOString(),
            status: 'passed',
          };
          try {
            if (step.op === 'navigate') {
              const stepUrl = new URL(step.route, target);
              if (stepUrl.hostname !== target.hostname)
                throw new Error('scenario navigation escaped the validated target');
              const response = await page.goto(stepUrl.toString(), {
                waitUntil: 'domcontentloaded',
                timeout: 40_000,
              });
              stepResult.navigationStatus = response?.status() ?? null;
              for (const selector of step.waitFor ?? [])
                await page.waitForSelector(selector, {
                  state: 'attached',
                  timeout: step.waitTimeoutMs ?? 15_000,
                });
            } else if (step.op === 'evaluate' || step.op === 'cleanup') {
              const evidence = await page.evaluate(step.run);
              if (!evidence || typeof evidence !== 'object') throw new Error(`${step.op} step returned no evidence`);
              stepResult.evidence = evidence;
            } else throw new Error(`unsupported operation: ${step.op}`);
            stepResult.assertions = assertEvidence(step, stepResult);
            if (stepResult.assertions.status === 'failed') throw new Error('assertion contract failed');
          } catch (error) {
            reportLocalError(`step ${scenario.name}/${step.name} failed`, error);
            stepResult.status = 'failed';
            Object.assign(stepResult, persistedError('step'));
            scenarioResult.status = 'failed';
          }
          stepResult.completedAt = new Date().toISOString();
          stepResult.screenshot = await captureScreenshot(
            page,
            outputDirectory,
            runId,
            scenarioIndex,
            scenario.name,
            stepIndex,
            step.name,
            stepResult.assertions?.status ?? 'not-run',
          );
          if (stepResult.screenshot.status === 'failed') scenarioResult.status = 'failed';
          scenarioResult.steps.push(stepResult);
        }
      } finally {
        try {
          await page.evaluate(() => window.__csdSim?.cleanupPage());
        } catch (error) {
          reportLocalError(`page cleanup ${scenario.name} failed`, error);
          cleanup.errors.push({
            scenario: scenario.name,
            ...persistedError('pageCleanup'),
          });
          scenarioResult.status = 'failed';
        }
        scenarioResult.finalScreenshot = await captureScreenshot(
          page,
          outputDirectory,
          runId,
          scenarioIndex,
          scenario.name,
          scenario.steps.length,
          'final',
          scenarioResult.status === 'passed' ? 'passed' : 'failed',
        );
        if (scenarioResult.finalScreenshot.status === 'failed') scenarioResult.status = 'failed';
        scenarioResult.network = [...requests.values()];
        scenarioResult.completedAt = new Date().toISOString();
        try {
          await context.close();
        } catch (error) {
          reportLocalError(`context cleanup ${scenario.name} failed`, error);
          cleanup.errors.push({
            scenario: scenario.name,
            ...persistedError('contextCleanup'),
          });
          scenarioResult.status = 'failed';
        }
        scenarioResults.push(scenarioResult);
      }
    }
  } finally {
    try {
      await browser.close();
      cleanup.browser = 'closed';
    } catch (error) {
      reportLocalError('browser cleanup failed', error);
      cleanup.browser = 'failed';
      cleanup.errors.push(persistedError('browserCleanup'));
    }
  }
  const receiptDirectory =
    selectedScenarios.length === 1
      ? resolve(outputDirectory, safeFilename(selectedScenarios[0].name))
      : outputDirectory;
  const receiptObjectKey =
    selectedScenarios.length === 1
      ? `runs/${runId}/${safeFilename(selectedScenarios[0].name)}/receipt.json`
      : `runs/${runId}/receipt.json`;
  const receipt = buildReceipt({
    runId,
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    scenarios: scenarioResults,
    cleanup,
    runtime: options.runtime ?? runtime?.runtime ?? {},
    objectKey: receiptObjectKey,
  });
  await mkdir(receiptDirectory, { recursive: true });
  const receiptPath = resolve(receiptDirectory, 'receipt.json');
  const temporaryPath = `${receiptPath}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(temporaryPath, receiptPath);
  return {
    receipt,
    receiptPath,
    exitCode: receipt.counts.failed === 0 && cleanup.errors.length === 0 ? 0 : 1,
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  try {
    const result = await runSuite();
    console.log(
      JSON.stringify({
        runId: result.receipt.runId,
        receipt: result.receiptPath,
        counts: result.receipt.counts,
      }),
    );
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(`ERROR: ${String(error.message || error)}`);
    process.exitCode = 1;
  }
}

export { EXPECTED_HOST };
