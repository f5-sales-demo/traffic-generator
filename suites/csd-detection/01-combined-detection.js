#!/usr/bin/env node
// CSD Detection driver — generates F5 XC Client-Side Defense statistics for the /csd-demo/ page.
//
// How CSD detection actually works (learned the hard way; see webapp-api-protection#166):
// CSD inventories EXTERNAL <script src> elements present AT PAGE LOAD and analyses their behaviour.
// It does NOT inventory inline <script> blocks, nor scripts injected dynamically after load. So the
// earlier approach here (injecting third-party <script> via page.evaluate after load) produced ZERO
// CSD statistics. The /csd-demo/ origin was fixed to serve external scripts at load:
//   - first-party checkout.js (reads payment fields → CSD flags it High Risk, like a Magecart skimmer)
//   - third-party CDN libraries (cdn.jsdelivr.net, unpkg.com → CSD records new third-party domains)
// This driver therefore just needs to drive a REAL browser through the page and interact with the
// form so checkout.js reads the field values — that is what CSD observes and flags.
//
// Steps: load /csd-demo/, fill the payment fields (triggers checkout.js field reads), dwell for the
// CSD telemetry beacon. Synchronous PASS asserts CSD is injected and reporting AND the origin is
// serving the external scripts CSD needs: CSD sensor GET __imp_apg__/js -> 200, telemetry beacon
// POST __imp_apg__/api/dip -> 200, first-party checkout.js -> 200, and >=1 third-party CDN -> 200.
// CSD statistics (suspicious_scripts / detected scripts) aggregate asynchronously on the CSD backend
// and are asserted separately by webapp-api-protection scripts/csd-verify.sh.
//
// Usage (via runner.sh): runner.sh csd-detection   (runner passes $TARGET_FQDN as argv[2])

const { chromium } = require('playwright');

const TARGET_FQDN = process.argv[2];
if (!TARGET_FQDN) {
  console.error('Usage: 01-combined-detection.js <TARGET_FQDN>');
  process.exit(1);
}
const BASE_URL = `${process.env.TARGET_PROTOCOL || 'http'}://${TARGET_FQDN}`;
const PAGE_URL = `${BASE_URL}/csd-demo/`;

// Payment fields the external checkout.js reads (the High Risk field-read signal).
const FIELDS = [
  ['ccNumber', '4111111111111111'],
  ['ccName', 'John Doe'],
  ['ccExpiry', '12/28'],
  ['ccCvv', '123'],
  ['email', 'john.doe@example.com'],
];

const isCsdJs = (u) => /__imp_apg__\/js\//.test(u);
const isBeacon = (u) => /__imp_apg__\/api\/dip/.test(u);
const isCheckoutJs = (u) => /\/csd-demo\/checkout\.js/.test(u);
const isThirdPartyCdn = (u) => /cdn\.jsdelivr\.net|unpkg\.com|esm\.sh|ga\.jspm\.io/.test(u);

(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    const responses = [];
    page.on('response', (r) => {
      const u = r.url();
      if (isCsdJs(u) || isBeacon(u) || isCheckoutJs(u) || isThirdPartyCdn(u)) {
        responses.push({ status: r.status(), url: u });
      }
    });

    await page.goto(PAGE_URL, { waitUntil: 'networkidle', timeout: 30000 });

    // Fill the payment form so the external checkout.js reads the field values (on input).
    let filled = 0;
    for (const [name, value] of FIELDS) {
      const el = (await page.$(`#${name}`)) || (await page.$(`[name="${name}"]`));
      if (el) {
        await el.fill(value);
        filled += 1;
      }
    }

    // Dwell so the CSD sensor observes the reads and flushes its telemetry beacon.
    await page.waitForTimeout(20000);

    const ok = (pred) => responses.find((r) => pred(r.url) && r.status === 200);
    const csdJs = ok(isCsdJs);
    const beacon = ok(isBeacon);
    const checkoutJs = ok(isCheckoutJs);
    const cdn = responses.filter((r) => isThirdPartyCdn(r.url) && r.status === 200);

    console.log(`[CSD Detection] filled ${filled}/${FIELDS.length} payment fields`);
    console.log(`[CSD Detection] CSD sensor JS: ${csdJs ? 200 : 'MISSING'}`);
    console.log(`[CSD Detection] CSD telemetry beacon (dip): ${beacon ? 200 : 'MISSING'}`);
    console.log(`[CSD Detection] first-party checkout.js: ${checkoutJs ? 200 : 'MISSING'}`);
    console.log(`[CSD Detection] third-party CDN scripts: ${cdn.length}`);

    if (!csdJs || !beacon) {
      console.error(
        'FAIL: CSD not injected/reporting (sensor or beacon missing). CSD not enabled/propagated on the LB.',
      );
      process.exit(1);
    }
    if (!checkoutJs) {
      console.error(
        'FAIL: origin did not serve external checkout.js — CSD has no first-party script to inventory (origin not fixed?).',
      );
      process.exit(1);
    }
    if (cdn.length === 0) {
      console.error('FAIL: no third-party CDN scripts loaded at page load — CSD cannot record third-party domains.');
      process.exit(1);
    }
    console.log(
      'PASS: CSD injected + reporting, and the page serves external scripts (checkout.js + CDN) for CSD to inventory.',
    );
    console.log('      Statistics aggregate async; verify with webapp-api-protection scripts/csd-verify.sh.');
    process.exit(0);
  } catch (err) {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  } finally {
    if (browser) await browser.close();
  }
})();
