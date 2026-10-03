#!/usr/bin/env node
// Automated scraping simulation via headless Chrome
// Tools: playwright
// Targets: Juice Shop product pages, DVWA, VAmPI
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
  console.error('Usage: 02-puppeteer-scraper.js <TARGET_FQDN>');
  process.exit(1);
}

const BASE_URL = `${process.env.TARGET_PROTOCOL || 'http'}://${TARGET_FQDN}`;

const PAGES_TO_SCRAPE = [
  '/juice-shop/',
  '/juice-shop/rest/products/search?q=',
  '/juice-shop/api/Products/',
  '/juice-shop/api/Feedbacks/',
  '/dvwa/',
  '/dvwa/setup.php',
  '/vampi/',
  '/vampi/users/v1',
  '/httpbin/get',
  '/whoami/',
  '/csd-demo/',
  '/health',
];

(async () => {
  console.log(`[*] Scraper simulation against ${TARGET_FQDN}`);
  console.log(`[*] Scraping ${PAGES_TO_SCRAPE.length} pages`);
  console.log('');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1920, height: 1080 },
  });
  const page = await context.newPage();
  const requestState = observeRequests(page);

  let scraped = 0;

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
      scraped++;
    } catch (err) {
      console.log(`    ERROR: ${err.message.substring(0, 80)}`);
    }
  }

  await settleRequests(requestState).catch(() => {
    process.exitCode = 1;
  });
  await browser.close();
  fs.rmSync(PROFILE_DIR, { recursive: true, force: true });

  console.log('');
  console.log(`[*] Scraping complete. Pages scraped: ${scraped}/${PAGES_TO_SCRAPE.length}`);
})();
