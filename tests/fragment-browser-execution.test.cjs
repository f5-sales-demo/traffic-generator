const assert = require('node:assert/strict');
const test = require('node:test');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

async function execute({ cleanupFailure = false, routeFailure = false, screenshotFailure = false } = {}) {
  const actions = [{ id: 'fragment-0', payload: 'synthetic' }];
  let receipt;
  let closed = false;
  const errors = [];
  const scenarioProcess = { env: { TARGET_URL: 'https://example.invalid/', TGEN_RESULTS_DIR: '/private/results' } };
  const page = {
    on() {},
    async goto() {},
    url: () => 'https://example.invalid/#/search?q=synthetic',
    async waitForSelector() {
      if (routeFailure) throw new Error('native route unavailable');
    },
    locator: () => ({ innerText: async () => 'A complete native application response with navigation' }),
    async screenshot() {
      if (screenshotFailure) throw new Error('native evidence write failed');
    },
  };
  const failed = new Set(
    cleanupFailure
      ? [{ url: () => 'https://example.invalid/socket.io/', failure: () => ({ errorText: 'net::ERR_ABORTED' }) }]
      : [],
  );
  await runInNewContext(readFileSync('scripts/fragment_browser.cjs', 'utf8'), {
    require(name) {
      if (name === 'playwright')
        return {
          chromium: {
            launch: async () => ({
              newPage: async () => page,
              close: async () => {
                closed = true;
              },
            }),
          },
        };
      if (name === 'node:path') return path;
      if (name === 'node:fs')
        return {
          readFileSync: () => JSON.stringify(actions),
          writeFileSync(filename, body, options) {
            assert.ok(filename.endsWith('route-actions.json'));
            assert.equal(options.mode, 0o600);
            receipt = JSON.parse(body);
          },
        };
      if (name === './browser_requests.cjs')
        return {
          observeRequests: () => ({ failed }),
          childHeaders: () => ({}),
          installSocketDrain: async () => {},
          settleRequests: async () => {},
          finishBrowserRequests: async () => {
            if (cleanupFailure) throw new Error('Native browser transport failed before cleanup completed');
          },
        };
      throw new Error(`Unexpected import: ${name}`);
    },
    __dirname: '/synthetic/scripts',
    process: scenarioProcess,
    console: { error: (message) => errors.push(message) },
  });
  return { receipt, closed, errors, exitCode: scenarioProcess.exitCode };
}

test('fragment workload persists native action evidence on successful cleanup', async () => {
  const result = await execute();
  assert.equal(result.closed, true);
  assert.equal(result.exitCode, undefined);
  assert.equal(result.receipt.browser_closed, true);
  assert.deepEqual(result.receipt.actions, [{ id: 'fragment-0', performed: true, rendered: true }]);
});

test('fragment cleanup failure persists actions and failed transport while rejecting workload', async () => {
  const result = await execute({ cleanupFailure: true });
  assert.equal(result.closed, true);
  assert.equal(result.exitCode, 1);
  assert.equal(result.receipt.browser_closed, true);
  assert.equal(result.receipt.actions[0].rendered, true);
  assert.match(result.receipt.cleanup_error, /transport failed/);
  assert.equal(result.receipt.failed_requests[0].error, 'net::ERR_ABORTED');
  assert.match(result.errors[0], /transport failed/);
});

test('fragment route failure remains failed and identifies the native error', async () => {
  const result = await execute({ routeFailure: true });
  assert.equal(result.exitCode, 1);
  assert.equal(result.receipt.actions[0].rendered, false);
  assert.equal(result.receipt.actions[0].error, 'native route unavailable');
});

test('fragment failure after rendered state cannot pass the native workload', async () => {
  const result = await execute({ screenshotFailure: true });
  assert.equal(result.exitCode, 1);
  assert.equal(result.receipt.actions[0].performed, true);
  assert.equal(result.receipt.actions[0].rendered, true);
  assert.equal(result.receipt.actions[0].error, 'native evidence write failed');
});
