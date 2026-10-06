#!/usr/bin/env node
// Automated scraping simulation via headless Chrome
// Tools: playwright
// Targets: Juice Shop product pages, DVWA, VAmPI
// Estimated duration: 1-2 minutes

const { chromium } = require('playwright');
const { observeRequests, settleRequests, childHeaders } = require('../../scripts/browser_requests.cjs');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const PROFILE_DIR = `/tmp/pw-profile-${path.basename(__filename, '.js')}-${process.pid}`;
process.on('exit', () => {
  try {
    fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
  } catch {}
});

const TARGET_FQDN = process.argv[2];
if (!TARGET_FQDN) {
  console.error('Usage: 02-puppeteer-scraper.js <TARGET_FQDN>');
  process.exit(1);
}

const BASE_URL = `${process.env.TARGET_PROTOCOL || 'http'}://${TARGET_FQDN}`;

const SCRAPE_PAGES = [
  {
    path: '/juice-shop/',
    text: 'Apple Juice',
  },
  {
    path: '/juice-shop/rest/products/search?q=',
    text: 'Apple Juice',
  },
  {
    path: '/juice-shop/api/Products/',
    text: 'data',
  },
  {
    path: '/juice-shop/api/Feedbacks/',
    text: 'data',
  },
  {
    path: '/dvwa/',
    text: 'DVWA',
  },
  {
    path: '/dvwa/setup.php',
    text: 'DVWA',
  },
  {
    path: '/vampi/',
    text: 'VAmPI',
  },
  {
    path: '/vampi/users/v1',
    text: 'username',
  },
  {
    path: '/httpbin/get',
    text: 'headers',
  },
  {
    path: '/whoami/',
    text: 'Hostname:',
  },
  {
    path: '/csd-demo/',
    text: 'Checkout',
  },
  {
    path: '/',
    text: 'Origin',
  },
];
const PAGES_TO_SCRAPE = SCRAPE_PAGES.map((item) => item.path);

(async () => {
  console.log(`[*] Scraper simulation against ${TARGET_FQDN}`);
  console.log(`[*] Scraping ${PAGES_TO_SCRAPE.length} pages`);
  console.log('');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const context = await browser.newContext({
    extraHTTPHeaders: childHeaders(),
    ignoreHTTPSErrors: true,
    viewport: { width: 1920, height: 1080 },
  });
  const page = await context.newPage();
  const requestState = observeRequests(page);

  let scraped = 0;
  let errors = 0;
  const directory = process.env.TGEN_RESULTS_DIR;
  if (!directory) throw new Error('Private results directory required');
  const receipt = {
    scenario: 'bot-simulation/02-puppeteer-scraper',
    source_commit: process.env.SOURCE_COMMIT,
    artifact_sha256: process.env.TGEN_ARTIFACT_SHA256,
    actions: [],
    browser_closed: false,
  };
  try {
    for (const path of PAGES_TO_SCRAPE) {
      try {
        const url = `${BASE_URL}${path}`;
        console.log(`[+] Scraping: ${path}`);

        await settleRequests(requestState);
        const response = await page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout: 10000,
        });
        const status = response ? response.status() : 'N/A';

        const title = await page.title();
        const textLen = await page.evaluate(() => document.body.innerText.length);
        const links = await page.evaluate(() => Array.from(document.querySelectorAll('a[href]')).length);

        console.log(`    HTTP ${status} | Title: ${title.substring(0, 40)} | Text: ${textLen} chars | Links: ${links}`);
        const expected = SCRAPE_PAGES.find((item) => item.path === path);
        await page.waitForFunction((term) => document.body.innerText.includes(term), expected.text, { timeout: 30000 });
        await settleRequests(requestState, 30000);
        const content = await page.locator('body').innerText();
        const screenshot = `scrape-${PAGES_TO_SCRAPE.indexOf(path)}.png`;
        await page.screenshot({ path: require('node:path').join(directory, screenshot) });
        const passed = status === 200 && content.includes(expected.text);
        receipt.actions.push({
          path,
          status,
          passed,
          content_matches: content.includes(expected.text),
          screenshot,
          response_sha256: crypto
            .createHash('sha256')
            .update(await response.body())
            .digest('hex'),
        });
        if (!passed) throw new Error('Native scrape content failed');
        scraped++;
      } catch (err) {
        console.log(`    ERROR: ${err.message.substring(0, 80)}`);
        errors++;
        if (!receipt.actions.some((item) => item.path === path)) receipt.actions.push({ path, passed: false });
      }
    }

    await settleRequests(requestState).catch(() => {
      process.exitCode = 1;
    });
  } finally {
    await browser.close();
    receipt.browser_closed = true;
    fs.writeFileSync(require('node:path').join(directory, 'scraper-functional.json'), JSON.stringify(receipt), {
      mode: 0o600,
    });
  }
  if (errors || scraped !== PAGES_TO_SCRAPE.length) process.exitCode = 1;
  fs.rmSync(PROFILE_DIR, { recursive: true, force: true });

  console.log('');
  console.log(`[*] Scraping complete. Pages scraped: ${scraped}/${PAGES_TO_SCRAPE.length}`);
})();
