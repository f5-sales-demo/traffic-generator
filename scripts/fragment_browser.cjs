// Perform each declared DOM XSS route action in Chromium, retaining private evidence.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const { observeRequests, settleRequests } = require('./browser_requests.cjs');
(async () => {
  const actions = JSON.parse(fs.readFileSync(path.join(__dirname, '../suites/fragment-actions.json')));
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ ignoreHTTPSErrors: true });
  const state = observeRequests(page);
  const receipt = { actions: [], browser_closed: false };
  page.on('dialog', async (dialog) => {
    await dialog.dismiss();
  });
  try {
    for (const action of actions) {
      const item = { id: action.id, performed: false, rendered: false };
      try {
        await page.goto(process.env.TARGET_URL + '#/search?q=' + encodeURIComponent(action.payload), {
          waitUntil: 'domcontentloaded',
          timeout: 20000,
        });
        item.performed = page.url().includes('#/search?q=');
        await page.waitForSelector('app-search-result', { timeout: 15000 });
        item.rendered = (await page.locator('body').innerText()).length > 30;
        await settleRequests(state);
        await page.screenshot({ path: path.join(process.env.TGEN_RESULTS_DIR, action.id + '.png') });
      } catch {
        item.error = 'browser route action failed';
      }
      receipt.actions.push(item);
    }
  } finally {
    await browser.close();
    receipt.browser_closed = true;
    fs.writeFileSync(path.join(process.env.TGEN_RESULTS_DIR, 'route-actions.json'), JSON.stringify(receipt), {
      mode: 0o600,
    });
  }
  if (receipt.actions.some((action) => !action.performed || !action.rendered)) process.exitCode = 1;
})().catch(() => {
  process.exitCode = 1;
});
