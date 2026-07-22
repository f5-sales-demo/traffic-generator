#!/usr/bin/env node
// CSD population driver — drives a POPULATION of distinct-fingerprint browser sessions against a
// CSD-instrumented page so F5 XC Client-Side Defense actually surfaces detections.
//
// WHY A POPULATION (root cause, established empirically 2026-07-21):
//   CSD surfaces a script only after it is observed across MULTIPLE DISTINCT USERS (distinct browser
//   fingerprints) AND the event-driven telemetry beacon has fired. A single automated client — even
//   headed real Chrome — stays below the surfacing threshold. This is why earlier single-shot drives
//   produced no statistics for 39h, while an 8-session distinct-fingerprint population produced
//   `suspicious_scripts` in ~20 minutes. The relevant signals CSD reports are per-script
//   `affected_users_count` and `form_fields_read` — i.e. behaving scripts seen by a population.
//
// WHAT MAKES A SESSION COUNT:
//   1. Distinct fingerprint: UA / locale / timezone / viewport varied per session (fresh context).
//   2. HEADED real Chrome (`channel:'chrome', headless:false`). Headless / datacenter traffic is
//      filtered by Shape's anti-automation — it exercises the sensor path (liveness) but will not
//      populate detections. Run HEADFUL from a real-client workstation over the VPN for real data.
//   3. The EVENT beacon must fire (>=2 `__imp_apg__/api/dip` beacons). The load beacon alone
//      (dip=1) does not report the script inventory. We trigger the event beacon with real keystroke
//      typing + toggling the demo's Attack Simulator so page scripts actively read fields.
//
// TARGET: defaults to `/csd-demo/` (CSD-instrumented checkout page). NOTE both `/csd-demo/` and
//   `/juice-shop/` receive the CSD sensor (js_insert=all_pages) — an earlier belief that only
//   `/juice-shop/` was injected was incorrect. Override with TARGET_PATH.
//
// Verification of the resulting detections is done by webapp-api-protection scripts/csd-verify.sh.
//
// Usage (via runner.sh): runner.sh csd-detection      (runner passes $TARGET_FQDN as argv[2])
//   HEADFUL=1     headed real Chrome (channel:chrome) — REQUIRED for actual detections
//   SESSIONS=8    number of distinct-fingerprint sessions (default 8)
//   TARGET_PATH=/csd-demo/   page to drive (default /csd-demo/)

const TARGET_FQDN = process.argv[2];
if (!TARGET_FQDN) {
  console.error('Usage: 02-population-detection.js <TARGET_FQDN>');
  process.exit(1);
}
const PROTO = process.env.TARGET_PROTOCOL || 'http';
const TARGET_PATH = process.env.TARGET_PATH || '/csd-demo/';
const URL = `${PROTO}://${TARGET_FQDN}${TARGET_PATH}`;
const N = parseInt(process.env.SESSIONS || '8', 10);
const HEADFUL = process.env.HEADFUL === '1';

// Prefer the full playwright package (bundled chromium); fall back to playwright-core + system Chrome.
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  ({ chromium } = require('playwright-core'));
}

const UAS = [
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
];
const LOCALES = ['en-US', 'en-GB', 'en-CA', 'en-AU'];
const TZ = ['America/New_York', 'America/Chicago', 'Europe/London', 'America/Los_Angeles', 'America/Toronto'];
const VPS = [
  { width: 1440, height: 900 },
  { width: 1536, height: 864 },
  { width: 1366, height: 768 },
  { width: 1920, height: 1080 },
  { width: 1280, height: 800 },
];
const pick = (a, i) => a[i % a.length];
const rnd = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Document-start stealth: strip the obvious automation tells so Shape does not filter the session.
const STEALTH = () => {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
  window.chrome = window.chrome || { runtime: {}, app: {}, csi: () => {}, loadTimes: () => {} };
};

async function session(idx) {
  const ua = pick(UAS, idx);
  const launchOpts = {
    headless: !HEADFUL,
    args: ['--no-sandbox', '--disable-blink-features=AutomationControlled', '--disable-dev-shm-usage'],
  };
  if (HEADFUL) launchOpts.channel = 'chrome';
  const browser = await chromium.launch(launchOpts);
  const context = await browser.newContext({
    userAgent: ua,
    locale: pick(LOCALES, idx),
    timezoneId: pick(TZ, idx),
    viewport: pick(VPS, idx),
    deviceScaleFactor: pick([1, 2, 1], idx),
    ignoreHTTPSErrors: true,
  });
  await context.addInitScript(STEALTH);
  const page = await context.newPage();
  page.on('dialog', (d) => d.dismiss().catch(() => {})); // never block on alert/confirm

  let sensor = false;
  const beacons = [];
  page.on('response', (r) => {
    const u = r.url();
    if (/__imp_apg__\/js\//.test(u)) sensor = true;
    if (/__imp_apg__\/api\/dip/.test(u)) beacons.push(r.status());
  });

  // Hard per-session cap so a stuck page can never stall the whole population.
  const guard = sleep(60000).then(() => {
    throw new Error('session timeout 60s');
  });
  const run = (async () => {
    await page.goto(URL, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await sleep(rnd(1500, 3000));
    for (let i = 0; i < rnd(3, 5); i++) {
      await page.mouse.move(rnd(60, 1100), rnd(80, 680), { steps: rnd(4, 9) });
      await sleep(rnd(120, 320));
    }
    await page.mouse.wheel(0, rnd(200, 800));
    // Toggle the demo Attack Simulator ON so page scripts actively read fields (fires event beacon).
    const toggles = await page.$$('input[type="checkbox"], .toggle, [role="switch"]');
    for (const t of toggles.slice(0, 5)) {
      await t.click({ timeout: 1500 }).catch(() => {});
      await sleep(rnd(150, 350));
    }
    // Fill inputs; real keystrokes on the first few (fire keydown/input events → event beacon).
    const inputs = await page.$$('input');
    let typed = 0;
    for (const el of inputs) {
      const type = (await el.getAttribute('type').catch(() => 'text')) || 'text';
      if (['hidden', 'submit', 'button', 'checkbox', 'radio'].includes(type)) continue;
      const val =
        type === 'email'
          ? `user${idx}@example.com`
          : type === 'password'
            ? `P@ss${idx}!23`
            : `demo${idx}${rnd(100, 999)}`;
      if (typed < 3) {
        await el.click({ timeout: 1500 }).catch(() => {});
        for (const ch of val.slice(0, 6)) {
          await page.keyboard.type(ch).catch(() => {});
          await sleep(rnd(40, 110));
        }
        await el.evaluate((n) => n.blur()).catch(() => {});
        typed++;
      } else {
        await el.fill(val, { timeout: 1500 }).catch(() => {});
      }
      await sleep(rnd(70, 180));
    }
    await sleep(rnd(6000, 9000)); // dwell for the event beacon + script telemetry
  })();

  try {
    await Promise.race([run, guard]);
    console.log(
      `[pop ${idx}] ua=${ua.slice(12, 20)} sensor=${sensor} dip=${beacons.length}${beacons.length >= 2 ? ' (event beacon ✓)' : ''}`,
    );
  } catch (e) {
    console.log(`[pop ${idx}] ${e.message.split('\n')[0]} (sensor=${sensor} dip=${beacons.length})`);
  } finally {
    await browser.close().catch(() => {});
  }
  return { sensor, twoBeacon: beacons.length >= 2 };
}

(async () => {
  console.log(
    `[CSD population] ${N} distinct-fingerprint sessions vs ${URL} — mode=${HEADFUL ? 'headed(real-chrome)' : 'headless(liveness)'}`,
  );
  let ok = 0;
  let evented = 0;
  for (let i = 0; i < N; i++) {
    const r = await session(i);
    if (r.sensor) ok++;
    if (r.twoBeacon) evented++;
    await sleep(rnd(800, 1800));
  }
  console.log(`[CSD population] DONE: ${N} sessions, sensor_ok=${ok}, event_beacon=${evented}`);
  if (ok === 0) {
    console.error('FAIL: CSD sensor never injected — CSD not enabled/propagated on the LB for this path.');
    process.exit(1);
  }
  if (!HEADFUL) {
    console.log(
      'NOTE: headless liveness run — sensor path exercised but detections will NOT populate. Run HEADFUL=1 from a real-client workstation for actual detections, then verify with webapp scripts/csd-verify.sh.',
    );
  } else if (evented === 0) {
    console.log(
      'NOTE: no session fired the event beacon (dip>=2); detections may not populate. Ensure the page has interactive form fields / Attack Simulator.',
    );
  } else {
    console.log(
      `PASS: ${evented}/${N} sessions fired the event beacon — detection signal sent; verify via csd-verify.sh (~20min aggregation).`,
    );
  }
  process.exit(0);
})();
