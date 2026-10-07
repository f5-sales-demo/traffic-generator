import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { join } from 'node:path';
import { projectHeaderPair, runHeaderPair } from '../suites/csd-violations/run.mjs';
import {
  APPROVED_CSD_COLLECTORS,
  HEADER_SCENARIO_SELECTORS,
  HEADER_VALUES,
  PAYMENT_PATH,
  SELECTOR_HEADER,
} from '../suites/csd-violations/scenarios.mjs';

// Explicit synthetic HTTPS transport fixture, NOT vendor sensor, live CSD,
// backend ingestion, baseline eligibility, alert acceptance or detection proof.
// No production guard is changed: canonical host/path and collector allowlist
// are resolved only inside this browser to the trusted loopback TLS listener.
assert.equal(process.platform, 'linux');
assert.notEqual(process.getuid(), 0, 'headed sandboxed Chrome must run nonprivileged');
const root = process.env.CSD_HEADER_FIXTURE_DIR;
assert.ok(root && process.env.CSD_TEST_PLAYWRIGHT_MODULE && process.env.DISPLAY);
const { chromium } = await import(process.env.CSD_TEST_PLAYWRIGHT_MODULE);
const host = 'client-side-defense.f5-sales-demo.com';
const collector = APPROVED_CSD_COLLECTORS[0];
const target = new URL(`https://${host}`);
const requests = [];
let failure = 'none';
let cancel;
const sensorPath = '/__imp_apg__/js/fixture-only.js';
const sensor = `/* Synthetic fixture adapter, not F5 vendor JavaScript. */
fetch('https://${collector.host}${collector.path}', {method:'POST', body:'fixture-only', mode:'cors', credentials:'omit'}).catch(() => {});
fetch('/fixture-asset', {cache:'no-store'}).catch(() => {});
fetch('${PAYMENT_PATH}?fixture=excluded', {method:'HEAD',cache:'no-store'}).catch(() => {});
`;
const fields = ['cardholder_name', 'card_number', 'expiry', 'cvv', 'billing_postal_code'];
const server = createServer(
  { key: await readFile(join(root, 'key.pem')), cert: await readFile(join(root, 'cert.pem')) },
  (req, res) => {
    const selected = req.headers[SELECTOR_HEADER.toLowerCase()];
    // Never retain/print headers, payloads, arbitrary URLs or request identifiers.
    const payment = req.url === PAYMENT_PATH && req.headers.host === host;
    const dip = req.url === collector.path && req.headers.host === collector.host;
    const sensorRequest = req.url === sensorPath && req.headers.host === host;
    requests.push({
      kind: payment ? 'payment' : dip ? 'collector' : sensorRequest ? 'sensor' : 'excluded',
      method: req.method,
      selected: selected ?? null,
      retained: req.headers.accept !== undefined,
    });
    res.setHeader('Access-Control-Allow-Origin', target.origin);
    res.setHeader('Vary', 'Origin');
    if (dip) {
      req.resume();
      if (failure === 'disconnect') {
        req.socket.destroy();
        return;
      }
      res.writeHead(failure === 'post503' ? 503 : 200, { 'Content-Type': 'text/plain' });
      res.end('fixture transport only');
      return;
    }
    if (payment) {
      for (const [name, value] of Object.entries(HEADER_VALUES)) if (name !== selected) res.setHeader(name, value);
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('X-Fixture-Retained', 'retained');
      res.writeHead(200);
      if (req.method === 'HEAD') {
        res.end();
        cancel?.();
        return;
      }
      res.end(
        `<!doctype html><title>Synthetic transport fixture</title><form>${fields.map((name) => `<input name="${name}" value="">`).join('')}</form><div data-csd-sensitive>Synthetic masked display</div><script src="${sensorPath}"></script>`,
      );
      return;
    }
    if (sensorRequest) {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(sensor);
      return;
    }
    // The query HEAD and asset are deliberate exclusion probes, not selectors.
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('fixture');
  },
);
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
let browser;
let captureNumber = 0;
const proof = {
  fixtureOnly: true,
  backendAcceptance: false,
  headed: true,
  sandboxRequested: true,
  pairs: [],
  failures: [],
};
try {
  browser = await chromium.launch({
    executablePath: process.env.CSD_TEST_CHROME_PATH || '/usr/bin/google-chrome',
    headless: false,
    chromiumSandbox: true,
    env: { ...process.env, HOME: root },
    args: [
      '--disable-dev-shm-usage',
      '--no-proxy-server',
      `--host-resolver-rules=MAP ${host} 127.0.0.1:${port}, MAP ${collector.host} 127.0.0.1:${port}`,
    ],
  });
  const observers = new WeakMap();
  const headDiagnostics = [];
  const observeHead = async (page) => {
    const session = await page.context().newCDPSession(page);
    const ids = new Set();
    session.on('Network.requestWillBeSent', (event) => {
      if (event.request.method === 'HEAD' && event.request.url === `${target.origin}${PAYMENT_PATH}`) {
        ids.add(event.requestId);
        headDiagnostics.push({ event: 'request', scriptInitiated: event.initiator?.type === 'script' });
      }
    });
    session.on('Network.loadingFinished', (event) => {
      if (ids.has(event.requestId)) headDiagnostics.push({ event: 'finished' });
    });
    session.on('Network.loadingFailed', (event) => {
      if (ids.has(event.requestId))
        headDiagnostics.push({
          event: 'failed',
          canceled: event.canceled === true,
          aborted: event.errorText === 'net::ERR_ABORTED',
        });
    });
    await session.send('Network.enable');
    observers.set(page, session);
  };
  const capture = async (page, mode, action) => {
    if (action === 'setup') await observeHead(page);
    if (action === 'cleanup') {
      await observers.get(page)?.detach();
      observers.delete(page);
    }
    const maskedInputCount = await page.locator('input,textarea,select').count();
    await page.locator('input,textarea,select').evaluateAll((controls) => {
      for (const control of controls) {
        control.value = '';
        control.removeAttribute('value');
        control.removeAttribute('placeholder');
      }
    });
    await page.locator('[data-csd-sensitive]').evaluateAll((nodes) => {
      for (const node of nodes) node.textContent = 'Synthetic masked display';
    });
    assert.equal(
      await page
        .locator('input,textarea,select')
        .evaluateAll((controls) => controls.some((control) => control.value !== '')),
      false,
    );
    const name = `${++captureNumber}-${mode}-${action}.png`;
    const bytes = await page.screenshot({ path: join(root, name), fullPage: true });
    await chmod(join(root, name), 0o600);
    return {
      status: 'captured',
      path: name,
      maskedInputCount,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  };
  const cleanupPassed = (pair) => {
    for (const phase of [pair.control, pair.mutation].filter(Boolean)) {
      assert.equal(phase.cleanup.fetchDisabled, true);
      assert.equal(phase.cleanup.sessionDetached, true);
      assert.equal(phase.cleanup.contextClosed, true);
      assert.deepEqual(phase.cleanup.errors, []);
    }
    assert.equal(browser.contexts().length, 0);
  };
  for (const [scenario, selector] of Object.entries(HEADER_SCENARIO_SELECTORS)) {
    const offset = requests.length;
    const pair = await runHeaderPair({ browser, target, selector, capture, operationTimeoutMs: 40_000 });
    await writeFile(join(root, `${scenario}.json`), JSON.stringify(pair), { mode: 0o600 });
    cleanupPassed(pair);
    if (pair.result !== 'passed') {
      proof.pairs.push({ ...projectHeaderPair(pair, scenario), diagnostic: 'canonical-runner-rejected-real-HEAD' });
      continue;
    }
    for (const phase of [pair.control, pair.mutation]) {
      assert.equal(phase.document.observed, true);
      assert.equal(phase.head.observed, true);
      assert.ok(phase.telemetry.finished > 0 && phase.telemetry.http2xx > 0);
      assert.equal(phase.sensor.finishedHttp2xx, 1);
      assert.equal(phase.screenshots.length, 6);
      for (const observation of [phase.document, phase.head])
        for (const name of Object.keys(HEADER_VALUES)) {
          assert.equal(observation.headers[name].present, !(phase.mode === 'mutation' && name === selector));
          assert.equal(observation.headers[name].matchesCanonical, !(phase.mode === 'mutation' && name === selector));
        }
    }
    const wire = requests.slice(offset);
    assert.equal(wire.filter((request) => request.selected === selector).length, 2);
    assert.ok(wire.some((request) => request.kind === 'excluded'));
    assert.ok(wire.some((request) => request.kind === 'collector' && request.method === 'POST'));
    assert.ok(wire.every((request) => request.retained));
    assert.ok(wire.filter((request) => request.kind !== 'payment').every((request) => request.selected === null));
    assert.doesNotMatch(
      JSON.stringify(pair),
      /fixture-only|nosniff|DENY|no-store|127\.0\.0\.1|requestId|rawHeaders|fixture=excluded/,
    );
    proof.pairs.push(projectHeaderPair(pair, scenario));
  }
  const documentPair = await runHeaderPair({
    browser,
    target,
    selector: 'x-frame-options',
    scope: 'document',
    capture,
  });
  cleanupPassed(documentPair);
  await writeFile(join(root, 'document-scope.json'), JSON.stringify(documentPair), { mode: 0o600 });
  proof.documentScope = documentPair.result;
  if (documentPair.result === 'passed')
    assert.equal(documentPair.mutation.head.headers['x-frame-options'].present, true);
  for (const mode of ['post503', 'disconnect', 'cancel']) {
    failure = mode;
    const controller = new AbortController();
    cancel = mode === 'cancel' ? () => controller.abort() : null;
    const pair = await runHeaderPair({
      browser,
      target,
      selector: 'cache-control',
      capture,
      signal: controller.signal,
    });
    cancel = null;
    await writeFile(join(root, `failure-${mode}.json`), JSON.stringify(pair), { mode: 0o600 });
    assert.equal(pair.result, 'failed');
    cleanupPassed(pair);
    if (mode === 'post503') assert.ok(pair.control.telemetry.httpNon2xx > 0);
    if (mode === 'disconnect') assert.ok(pair.control.telemetry.failed > 0);
    if (mode === 'cancel') assert.equal(pair.pairCompletedAt, null);
    proof.failures.push({ mode, result: pair.result, cleanup: 'passed' });
    failure = 'none';
    const recovery = await runHeaderPair({ browser, target, selector: 'cache-control', capture });
    cleanupPassed(recovery);
    proof.failures.at(-1).recovery = recovery.result;
  }
  proof.headDiagnostics = headDiagnostics;
  await writeFile(join(root, 'proof.json'), JSON.stringify(proof), { mode: 0o600 });
  assert.equal(proof.pairs.filter((pair) => pair.result === 'passed').length, 3, 'FIXTURE_THREE_PAIR_GATE_FAILED');
  assert.equal(proof.documentScope, 'passed', 'FIXTURE_DOCUMENT_SCOPE_FAILED');
  assert.ok(
    proof.failures.every((failure) => failure.recovery === 'passed'),
    'FIXTURE_RECOVERY_FAILED',
  );
  console.log(
    'PASS fixture-only: 3 headed HTTPS header pairs; document scope; failed POST/non2xx/cancel cleanup and recovery; no CSD acceptance claim',
  );
} finally {
  await browser?.close();
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
