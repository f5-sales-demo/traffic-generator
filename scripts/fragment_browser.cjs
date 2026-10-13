// Perform each declared DOM XSS route action in Chromium, retaining private evidence.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const {
  observeRequests,
  settleRequests,
  childHeaders,
  installSocketDrain,
  finishBrowserRequests,
} = require('./browser_requests.cjs');
(async () => {
  const actions = JSON.parse(fs.readFileSync(path.join(__dirname, '../suites/fragment-actions.json')));
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ ignoreHTTPSErrors: true, extraHTTPHeaders: childHeaders() });
  await installSocketDrain(page);
  const state = observeRequests(page);
  const receipt = { actions: [], browser_closed: false };
  page.on('dialog', async (dialog) => {
    await dialog.dismiss();
  });
  try {
    for (const action of actions) {
      const item = { id: action.id, performed: false, rendered: false };
      try {
        await page.goto(`${process.env.TARGET_URL}#/search?q=${encodeURIComponent(action.payload)}`, {
          waitUntil: 'domcontentloaded',
          timeout: 20000,
        });
        item.performed = page.url().includes('#/search?q=');
        await page.waitForSelector('app-search-result', { timeout: 15000 });
        item.rendered = (await page.locator('body').innerText()).length > 30;
        await settleRequests(state);
        await page.screenshot({ path: path.join(process.env.TGEN_RESULTS_DIR, `${action.id}.png`) });
      } catch (error) {
        item.error = error.message;
      }
      receipt.actions.push(item);
    }
  } finally {
    try {
      await finishBrowserRequests(page, state);
    } catch (error) {
      receipt.cleanup_error = error.message;
      throw error;
    } finally {
      receipt.failed_requests = Array.from(state.failed, (request) => ({
        url: request.url(),
        error: request.failure()?.errorText || 'Native browser request failed',
      }));
      try {
        await browser.close();
        receipt.browser_closed = true;
      } finally {
        fs.writeFileSync(path.join(process.env.TGEN_RESULTS_DIR, 'route-actions.json'), JSON.stringify(receipt), {
          mode: 0o600,
        });
      }
    }
  }
  if (receipt.actions.some((action) => !action.performed || !action.rendered)) process.exitCode = 1;
})().catch((error) => {
  console.error(`[FAIL] Native browser workload: ${error.message}`);
  process.exitCode = 1;
});
