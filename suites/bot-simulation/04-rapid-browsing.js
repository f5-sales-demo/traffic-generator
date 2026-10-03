#!/usr/bin/env node
// Rapid page navigation simulation (bot behavior)
// Tools: playwright
// Targets: Various application pages at high speed
// Estimated duration: 1-2 minutes

const { chromium } = require('playwright');
const { observeRequests, settleRequests, childHeaders } = require('../../scripts/browser_requests.cjs');
const path = require('node:path');
const fs = require('node:fs');
const { navigation, verifyNavigation } = require('../../scripts/rapid_navigation.cjs');
const PROFILE_DIR = `/tmp/pw-profile-${path.basename(__filename, '.js')}-${process.pid}`;
process.on('exit', () => {
  try {
    fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
  } catch {}
});

const TARGET_FQDN = process.argv[2];
if (!TARGET_FQDN) {
  console.error('Usage: 04-rapid-browsing.js <TARGET_FQDN>');
  process.exit(1);
}

const BASE_URL = `${process.env.TARGET_PROTOCOL || 'http'}://${TARGET_FQDN}`;

// Pages to hit rapidly
const PAGES = navigation.map((item) => item.path);

// Rotating user agents
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
  'curl/8.0.0',
  'python-requests/2.31.0',
  'Go-http-client/2.0',
  'Java/17.0.1',
  'Wget/1.21',
  'Scrapy/2.11',
  'axios/1.6.0',
  'httpx/0.25.0',
  'Apache-HttpClient/4.5.14',
  'okhttp/4.12.0',
];

(async () => {
  console.log(`[*] Rapid browsing simulation against ${TARGET_FQDN}`);
  console.log(`[*] Hitting ${PAGES.length} pages with ${USER_AGENTS.length} user agents`);
  console.log('');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors'],
  });

  const directory = process.env.TGEN_RESULTS_DIR;
  if (!directory) throw new Error('Private results directory is required');
  const receipt = { actions: [], browser_closed: false };
  let visited = 0;
  let errors = 0;
  const startTime = Date.now();

  try {
    for (const [identity, ua] of USER_AGENTS.entries()) {
      const context = await browser.newContext({
        extraHTTPHeaders: childHeaders(),
        ignoreHTTPSErrors: true,
        userAgent: ua,
      });
      const page = await context.newPage();
      const requestState = observeRequests(page);
      let documentResponse;
      const browserErrors = [];
      page.on('pageerror', () => browserErrors.push({ kind: 'console-error' }));
      page.on('requestfailed', (request) =>
        browserErrors.push({
          kind: 'request-failure',
          path: new URL(request.url()).pathname,
        }),
      );
      page.on('response', (response) => {
        if (response.status() >= 400)
          browserErrors.push({
            kind: 'http-error',
            path: new URL(response.url()).pathname,
            status: response.status(),
          });
      });
      page.setDefaultTimeout(10000);

      const uaShort = ua.length > 40 ? `${ua.substring(0, 40)}...` : ua;
      console.log(`[+] UA: ${uaShort}`);

      for (const path of PAGES) {
        try {
          const url = `${BASE_URL}${path}`;
          await settleRequests(requestState);
          if (new URL(url).hash) {
            await page.goto('about:blank');
            documentResponse = undefined;
          }
          const response = await page.goto(url, {
            waitUntil: 'domcontentloaded',
            timeout: 20000,
          });
          if (response) documentResponse = response;
          const status = response ? response.status() : 'N/A';
          console.log(`    ${path} -> ${status}`);
          await settleRequests(requestState);
          const item = await verifyNavigation(
            page,
            response || documentResponse,
            path,
            identity,
            directory,
            Boolean(response),
          );
          receipt.actions.push(item);
          if (!item.rendered && !item.mitigated) throw new Error('Declared navigation outcome was not rendered');
          visited++;
        } catch (err) {
          const id = `ua-${identity}-route-${PAGES.indexOf(path)}`;
          await page.screenshot({ path: require('node:path').join(directory, `${id}-failed.png`) }).catch(() => {});
          receipt.actions.push({
            id,
            performed: false,
            attempted: true,
            rendered: false,
            error: 'browser-route-failure',
            status: documentResponse?.status(),
            document_bytes: documentResponse
              ? (await documentResponse.body().catch(() => Buffer.alloc(0))).length
              : null,
            scripts: await page
              .locator('script[src]')
              .count()
              .catch(() => 0),
            browser_errors: [...browserErrors],
            body_characters: (
              await page
                .locator('body')
                .innerText()
                .catch(() => '')
            ).length,
          });
          console.log(`    ${path} -> ERR: ${err.message.substring(0, 60)}`);
          errors++;
        }
        // Minimal delay between requests (bot behavior)
        await page.waitForTimeout(50).catch(() => {});
      }

      await settleRequests(requestState).catch(() => {
        errors++;
      });
      receipt.browser_errors = [...(receipt.browser_errors || []), ...browserErrors];
      fs.writeFileSync(require('node:path').join(directory, 'route-actions.json'), JSON.stringify(receipt), {
        mode: 0o600,
      });
      await context.close();
      console.log('');
    }
  } finally {
    await browser.close();
    receipt.browser_closed = true;
    fs.writeFileSync(path.join(directory, 'route-actions.json'), JSON.stringify(receipt), { mode: 0o600 });
  }
  fs.rmSync(PROFILE_DIR, { recursive: true, force: true });

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const rate = ((visited / elapsed) * 1).toFixed(1);

  console.log('[*] Rapid browsing simulation complete');
  console.log(`    Pages visited: ${visited} | Errors: ${errors}`);
  if (errors) process.exitCode = 1;
  console.log(`    Duration: ${elapsed}s | Rate: ${rate} req/s`);
})();
