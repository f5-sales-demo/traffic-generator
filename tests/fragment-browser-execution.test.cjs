const assert = require('node:assert/strict');
const test = require('node:test');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

async function execute({
  cleanupFailure = false,
  routeFailure = false,
  screenshotFailure = false,
  cacheFailure = false,
  bufferFailure = false,
  forwardingFailure = false,
} = {}) {
  const actions = [{ id: 'fragment-0', payload: 'synthetic' }];
  let receipt;
  let closed = false;
  const errors = [];
  const events = [];
  const scenarioProcess = { env: { TARGET_URL: 'https://example.invalid/', TGEN_RESULTS_DIR: '/private/results' } };
  const page = {
    on() {},
    context: () => ({
      newCDPSession: async (target) => {
        assert.equal(target, page);
        return {
          async send(command, parameters) {
            assert.equal(command, 'Network.setCacheDisabled');
            assert.equal(parameters.cacheDisabled, true);
            events.push('disable-cache');
            if (cacheFailure) throw new Error('native cache isolation unavailable');
          },
        };
      },
    }),
    async goto() {
      events.push('navigate');
    },
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
      if (name === './browser_live_responses.cjs')
        return {
          installLiveResponseBuffer: async (target, value) => {
            assert.equal(target, page);
            value.live_response_buffering = false;
            value.buffered_responses = [];
            if (bufferFailure) throw new Error('native buffering unavailable');
            value.live_response_buffering = true;
            if (forwardingFailure) value.buffered_responses.push({ fulfilled: false, error: 'Error' });
            events.push('buffer-responses');
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
  return { receipt, closed, errors, events, exitCode: scenarioProcess.exitCode };
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

test('fragment actions disable HTTP cache before any native navigation', async () => {
  const result = await execute();
  assert.deepEqual(result.events, ['disable-cache', 'buffer-responses', 'navigate']);
  assert.equal(result.receipt.http_cache_disabled, true);
  assert.equal(result.receipt.failed_requests.length, 0);
});

test('cache isolation failure rejects workload and preserves browser cleanup evidence', async () => {
  const result = await execute({ cacheFailure: true });
  assert.equal(result.exitCode, 1);
  assert.equal(result.closed, true);
  assert.equal(result.receipt.browser_closed, true);
  assert.equal(result.receipt.http_cache_disabled, false);
  assert.equal(result.receipt.actions.length, 0);
  assert.deepEqual(result.events, ['disable-cache']);
  assert.match(result.errors[0], /cache isolation unavailable/);
});

test('buffer installation failure rejects workload while retaining cleanup evidence', async () => {
  const result = await execute({ bufferFailure: true });
  assert.equal(result.exitCode, 1);
  assert.equal(result.closed, true);
  assert.equal(result.receipt.live_response_buffering, false);
  assert.equal(result.receipt.actions.length, 0);
});

test('failed native forwarding rejects even a rendered action and successful browser cleanup', async () => {
  const result = await execute({ forwardingFailure: true });
  assert.equal(result.exitCode, 1);
  assert.equal(result.receipt.actions[0].rendered, true);
  assert.equal(result.receipt.browser_closed, true);
  assert.equal(result.receipt.buffered_responses[0].fulfilled, false);
});
