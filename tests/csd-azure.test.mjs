import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { azureRoutes, validateAzure } from '../suites/csd-violations/azure.mjs';
import { waitForRequestsTerminal } from '../suites/csd-violations/run.mjs';

const environment = {
  SOURCE_COMMIT: 'a'.repeat(40),
  TGEN_ARTIFACT_SHA256: 'b'.repeat(64),
  TARGET_URL: 'https://www.example.test/juice-shop/',
  TGEN_AUTHORIZED_HOST: 'www.example.test',
  TGEN_RESULTS_DIR: '/tmp/private-evidence',
};
test('Azure browser requires immutable provenance and exact authorized WAAP path', () => {
  assert.equal(validateAzure(environment).pathname, '/juice-shop/');
  for (const change of [
    { SOURCE_COMMIT: 'main' },
    { TARGET_URL: 'https://outside.example.test/juice-shop/' },
    { TARGET_URL: 'http://www.example.test/juice-shop/' },
    { TARGET_URL: 'https://www.example.test/' },
    { TGEN_RESULTS_DIR: 'relative' },
  ]) {
    assert.throws(() => validateAzure({ ...environment, ...change }));
  }
});

test('browser cleanup waits for application assets and fails unresolved requests', async () => {
  const request = { path: '/juice-shop/assets/product.jpg', terminal: 'pending' };
  const requests = new Map([[1, request]]);
  assert.equal((await waitForRequestsTerminal(requests, 1)).passed, false);
  setTimeout(() => {
    request.terminal = 'finished';
  }, 10);
  assert.equal((await waitForRequestsTerminal(requests, 100)).passed, true);
  requests.set(2, { path: '/juice-shop/socket.io/', terminal: 'pending' });
  assert.equal((await waitForRequestsTerminal(requests, 1)).passed, true);
});

test('Azure shutdown blocks late asset dispatch without hiding failed in-flight requests', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'csd-route-cleanup-'));
  try {
    const routes = azureRoutes(new URL(environment.TARGET_URL), { ...environment, TGEN_RESULTS_DIR: directory });
    let handler;
    let continued = 0;
    let aborted = 0;
    await routes.routeSetup({
      route: async (_pattern, callback) => {
        handler = callback;
      },
    });
    const request = (url) => ({
      request: () => ({ url: () => url }),
      continue: () => {
        continued += 1;
      },
      abort: () => {
        aborted += 1;
      },
    });
    await handler(request('https://www.example.test/csd-demo/static/vendor/lodash.min.js'));
    await handler(request('https://outside.example.test/asset.js'));
    await routes.routeCleanup();
    await handler(request('https://www.example.test/csd-demo/static/vendor/lodash.min.js'));
    assert.equal(continued, 1);
    assert.equal(aborted, 2);
  } finally {
    await rm(directory, { recursive: true });
  }
});
