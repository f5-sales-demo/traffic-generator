#!/usr/bin/env node
// Credential stuffing simulation via headless Chrome
// Tools: playwright (Node.js)
// Targets: DVWA native login form
// Estimated duration: 1-2 minutes

const { chromium } = require('playwright');
const { observeRequests, settleRequests, childHeaders } = require('../../scripts/browser_requests.cjs');
const path = require('node:path');
const fs = require('node:fs');
const PROFILE_DIR = `/tmp/pw-profile-${path.basename(__filename, '.js')}-${process.pid}`;
process.on('exit', () => {
  try {
    fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
  } catch {}
});

const TARGET_FQDN = process.argv[2];
if (!TARGET_FQDN) {
  console.error('Usage: 01-playwright-credential-stuff.js <TARGET_FQDN>');
  process.exit(1);
}

const BASE_URL = `${process.env.TARGET_PROTOCOL || 'http'}://${TARGET_FQDN}`;

// Common credential pairs for stuffing simulation (targets DVWA standard HTML form)
const CREDENTIALS = [
  { user: 'admin', password: 'password' },
  { user: 'admin', password: 'admin' },
  { user: 'admin', password: '123456' },
  { user: 'admin', password: 'letmein' },
  { user: 'admin', password: 'admin123' },
  { user: 'root', password: 'toor' },
  { user: 'test', password: 'test' },
  { user: 'user', password: 'user' },
  { user: 'guest', password: 'guest' },
  { user: 'admin', password: 'password123' },
  { user: 'admin', password: 'qwerty' },
  { user: 'admin', password: 'abc123' },
  { user: 'operator', password: 'operator' },
  { user: 'admin', password: '1234' },
  { user: 'admin', password: 'pass' },
];

(async () => {
  console.log(`[*] Credential stuffing simulation against ${TARGET_FQDN}`);
  console.log(`[*] Testing ${CREDENTIALS.length} credential pairs`);
  console.log('');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors'],
  });

  let successes = 0;
  let failures = 0;
  let launched = 0;
  let transportFailures = 0;
  const attempts = [];
  const browserErrors = [];
  const screenshots = [];
  const resultsDir = process.env.TGEN_RESULTS_DIR;
  if (resultsDir) fs.mkdirSync(resultsDir, { recursive: true, mode: 0o700 });

  for (const cred of CREDENTIALS) {
    const context = await browser.newContext({
      extraHTTPHeaders: childHeaders(),
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    const requestState = observeRequests(page);
    page.on('pageerror', (error) => browserErrors.push(error.name));
    page.on('requestfailed', () => browserErrors.push('requestfailed'));
    const attemptIndex = CREDENTIALS.indexOf(cred);
    const expectedAccepted = attemptIndex === 0;
    page.setDefaultTimeout(60000);

    try {
      console.log(`[+] Trying: ${cred.user} / ${cred.password}`);

      for (let setupAttempt = 0; setupAttempt < 3; setupAttempt++) {
        const setup = await page.goto(`${BASE_URL}/dvwa/login.php`, {
          waitUntil: 'domcontentloaded',
          timeout: 60000,
        });
        if (![502, 503, 504].includes(setup.status())) break;
        console.log(`    -> SETUP FAILURE: HTTP ${setup.status()} on attempt ${setupAttempt + 1}`);
        await settleRequests(requestState, 60000);
        await page.waitForTimeout(1000);
      }

      const hasForm = await page.$('input[name="username"]');
      if (!hasForm) {
        const body = await page.textContent('body').catch(() => '');
        if (body.includes('Connection refused') || body.includes('Fatal error')) {
          console.log(`    -> FAIL: DVWA database is down (MySQL connection refused on origin server)`);
          console.log(`    -> BOTTLENECK: Origin server DVWA container MySQL needs restart`);
        } else {
          console.log(`    -> FAIL: Login form not rendered (unexpected page state)`);
        }
        failures++;
        continue;
      }

      await settleRequests(requestState, 60000);
      await page.fill('input[name="username"]', cred.user);
      await page.fill('input[name="password"]', cred.password);
      const [response] = await Promise.all([
        page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 60000 }),
        page.click('input[type="submit"]'),
      ]);
      launched++;
      await settleRequests(requestState, 60000);
      const body = await page.textContent('body');
      const route = new URL(page.url()).pathname;
      const accepted =
        response.status() === 200 && route === '/dvwa/index.php' && body.includes('DVWA') && body.includes('Logout');
      const rejected =
        response.status() === 200 &&
        route === '/dvwa/login.php' &&
        body.includes('DVWA') &&
        body.includes('Login failed');
      if (resultsDir) {
        const filename = `credential-${String(attemptIndex).padStart(2, '0')}.png`;
        await page.screenshot({ path: path.join(resultsDir, filename), fullPage: true });
        fs.chmodSync(path.join(resultsDir, filename), 0o600);
        screenshots.push(filename);
      }
      let sessionClosed = !accepted;
      if (accepted) {
        successes++;
        const logout = await page.goto(`${BASE_URL}/dvwa/logout.php`, {
          waitUntil: 'domcontentloaded',
          timeout: 60000,
        });
        await settleRequests(requestState, 60000);
        sessionClosed =
          logout.status() === 200 &&
          new URL(page.url()).pathname === '/dvwa/login.php' &&
          (await page.locator('input[name="username"]').count()) === 1;
      } else failures++;
      const passed = (expectedAccepted ? accepted : rejected) && sessionClosed;
      attempts.push({ index: attemptIndex, expectedAccepted, accepted, rejected, sessionClosed, passed });
      console.log(`    -> Native outcome: ${accepted ? 'accepted' : rejected ? 'rejected' : 'unverified'}`);
    } catch (err) {
      console.log(`    -> ERROR: ${err.message}`);
      console.log(
        `    -> Pending paths: ${JSON.stringify([...requestState.pending].map((request) => new URL(request.url()).pathname))}`,
      );
      failures++;
      transportFailures++;
    } finally {
      await settleRequests(requestState, 60000).catch(() => {
        transportFailures++;
      });
      await context.close();
    }
  }

  await browser.close();
  if (resultsDir) {
    const receipt = {
      scenario: 'bot-simulation/01-playwright-credential-stuff',
      source_commit: process.env.SOURCE_COMMIT,
      passed:
        attempts.length === CREDENTIALS.length &&
        attempts.every((attempt) => attempt.passed) &&
        browserErrors.length === 0 &&
        transportFailures === 0,
      attempts,
      browserErrors,
      screenshots,
      contextsClosed: true,
    };
    const receiptPath = path.join(resultsDir, 'credential-functional.json');
    fs.writeFileSync(receiptPath, JSON.stringify(receipt));
    fs.chmodSync(receiptPath, 0o600);
  }
  fs.rmSync(PROFILE_DIR, { recursive: true, force: true });

  console.log('');
  console.log('[*] Credential stuffing simulation complete');
  console.log(`    Successes: ${successes} | Failures: ${failures}`);
  console.log(`    Credentials submitted: ${launched}`);
  if (process.env.TGEN_INHERITED_BOUNDARY === '1' && (launched !== CREDENTIALS.length || transportFailures))
    process.exitCode = 1;
})();
