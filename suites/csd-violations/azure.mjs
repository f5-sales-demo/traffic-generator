#!/usr/bin/env node
import { constants, realpathSync } from 'node:fs';
import { access, writeFile } from 'node:fs/promises';
// Azure launches reuse the browser engine. AWS remains governed by validateAwsRuntime.
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { runSuite, validateTarget } from './run.mjs';
import { REVIEWED_DESTINATIONS } from './scenarios.mjs';

const NATIVE_SCRIPTS = Object.freeze({
  'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js': 'lodash.min.js',
  'https://esm.sh/moment@2.30.1': 'moment.js',
  'https://unpkg.com/underscore@1.13.7/underscore-min.js': 'underscore-min.js',
  'https://ga.jspm.io/npm:dayjs@1.11.13/dayjs.min.js': 'dayjs.min.js',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js': 'chart.umd.min.js',
});

export function validateAzure(environment) {
  if (
    !/^[a-f0-9]{40}$/.test(environment.SOURCE_COMMIT ?? '') ||
    !/^[a-f0-9]{64}$/.test(environment.TGEN_ARTIFACT_SHA256 ?? '')
  )
    throw new Error('Azure simulation requires immutable source provenance');
  const target = validateTarget(environment.TARGET_URL, environment.TGEN_AUTHORIZED_HOST);
  if (target.pathname !== '/juice-shop/') throw new Error('Azure simulation requires the authorized Juice Shop route');
  if (!environment.TGEN_RESULTS_DIR?.startsWith('/')) throw new Error('Private absolute output directory is required');
  return target;
}

export async function runAzure(environment = process.env, options = {}) {
  const target = validateAzure(environment);
  const require = createRequire(import.meta.url);
  const playwright = options.playwright ?? require('playwright');
  const chrome = environment.CHROME_PATH ?? playwright.chromium.executablePath();
  if (!options.playwright) await access(chrome, constants.X_OK);
  return runSuite({
    playwright,
    expectedHost: target.hostname,
    targetUrl: target.toString(),
    routePrefix: '/juice-shop',
    outputDirectory: environment.TGEN_RESULTS_DIR,
    runId: environment.RUN_ID,
    scenario: environment.CSD_SCENARIO,
    executablePath: chrome,
    headless: true,
    drainRequests: true,
    browserArgs: ['--disable-dev-shm-usage', '--no-sandbox'],
    ignoreHTTPSErrors: true, // Only the task-owned pacing proxy certificate is intercepted.
    runtime: {
      platform: 'azure',
      sourceCommit: environment.SOURCE_COMMIT,
      artifactDigest: environment.TGEN_ARTIFACT_SHA256,
      csdEnabled: false,
    },
    routeCleanup: async (context) => {
      await context.unrouteAll({ behavior: 'wait' });
      await writeFile(
        resolve(environment.TGEN_RESULTS_DIR, 'browser-cleanup.json'),
        JSON.stringify({
          sourceCommit: environment.SOURCE_COMMIT,
          phase: 'closing-browser',
        }),
        { mode: 0o600 },
      );
    },
    routeSetup: async (context) => {
      await context.route('**/*', async (route) => {
        const url = new URL(route.request().url());
        if (url.hostname === target.hostname) return route.continue();
        if (!REVIEWED_DESTINATIONS.includes(url.hostname)) return route.abort('blockedbyclient');
        // Keep reviewed synthetic counters/loader attempts on the authorized WAAP route.
        const script = NATIVE_SCRIPTS[url.href];
        if (route.request().resourceType() === 'script' && !script)
          throw new Error('Reviewed native script asset missing');
        const destination = script
          ? `/csd-demo/static/vendor/${script}`
          : route.request().method() === 'POST'
            ? '/httpbin/post'
            : '/httpbin/get';
        const response = await route.fetch({ url: `${target.origin}${destination}`, maxRetries: 2, timeout: 60000 });
        if (script && (response.status() !== 200 || !response.headers()['content-type']?.includes('javascript')))
          throw new Error('Native script response failed');
        return route.fulfill({ response });
      });
    },
    ...options,
  });
}

if (process.argv[1] && realpathSync(resolve(process.argv[1])) === new URL(import.meta.url).pathname) {
  try {
    const result = await runAzure();
    console.log(JSON.stringify({ counts: result.receipt.counts, receipt: result.receiptPath, csdEnabled: false }));
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(String(error.message));
    process.exitCode = 1;
  }
}
