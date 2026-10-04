#!/usr/bin/env node
import { constants, realpathSync } from 'node:fs';
import { access, writeFile } from 'node:fs/promises';
// Azure launches reuse the browser engine. AWS remains governed by validateAwsRuntime.
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { runSuite, validateTarget } from './run.mjs';

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
        return route.abort('blockedbyclient');
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
