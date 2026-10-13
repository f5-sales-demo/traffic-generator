const assert = require('node:assert/strict');
const test = require('node:test');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const source = readFileSync('suites/bot-simulation/01-playwright-credential-stuff.js', 'utf8');

async function executeCredentialScenario({ missingForm = false, retrySetup = false, browserError = false } = {}) {
  const submissions = [];
  const navigations = [];
  const logs = [];
  const contexts = [];
  let browserClosed = false;
  let receipt;
  const scenarioProcess = {
    argv: ['node', 'credential-scenario.js', 'example.invalid'],
    env: { TARGET_PROTOCOL: 'https', TGEN_INHERITED_BOUNDARY: '1', TGEN_RESULTS_DIR: '/synthetic/results' },
    pid: 12345,
    on() {},
  };
  const browser = {
    async newContext() {
      const fields = {};
      let setupAttempts = 0;
      const context = { closed: false };
      let route = '/dvwa/login.php';
      const page = Object.assign(new EventEmitter(), {
        setDefaultTimeout() {},
        async goto(url, options) {
          assert.ok(
            ['https://example.invalid/dvwa/login.php', 'https://example.invalid/dvwa/logout.php'].includes(url),
          );
          route = '/dvwa/login.php';
          if (browserError) page.emit('pageerror', new Error('synthetic browser error'));
          assert.equal(options.waitUntil, 'domcontentloaded');
          assert.equal(options.timeout, 60000);
          navigations.push(url);
          setupAttempts++;
          return { status: () => (retrySetup && setupAttempts === 1 ? 503 : 200) };
        },
        async $(selector) {
          assert.equal(selector, 'input[name="username"]');
          return missingForm ? null : {};
        },
        async textContent() {
          return missingForm
            ? 'Unexpected landing page'
            : route === '/dvwa/index.php'
              ? 'DVWA Logout'
              : 'DVWA Login failed';
        },
        async fill(selector, value) {
          fields[selector] = value;
        },
        async click(selector) {
          assert.equal(selector, 'input[type="submit"]');
          route =
            fields['input[name="username"]'] === 'admin' && fields['input[name="password"]'] === 'password'
              ? '/dvwa/index.php'
              : '/dvwa/login.php';
          submissions.push({
            user: fields['input[name="username"]'],
            password: fields['input[name="password"]'],
          });
        },
        async waitForTimeout() {},
        async waitForNavigation() {
          return { status: () => 200 };
        },
        async screenshot() {},
        locator: () => ({ count: async () => 1 }),
        url: () => `https://example.invalid${route}`,
      });
      context.newPage = async () => page;
      context.close = async () => {
        context.closed = true;
      };
      contexts.push(context);
      return context;
    },
    async close() {
      browserClosed = true;
    },
  };
  await runInNewContext(source, {
    URL,
    require(name) {
      if (name === 'playwright') return { chromium: { launch: async () => browser } };
      if (name.endsWith('browser_requests.cjs'))
        return {
          observeRequests: () => ({ pending: new Set() }),
          settleRequests: async () => {},
          childHeaders: () => ({}),
        };
      if (name === 'node:path') return path;
      if (name === 'node:fs')
        return {
          rmSync() {},
          mkdirSync() {},
          chmodSync() {},
          writeFileSync(filename, body) {
            if (filename.endsWith('credential-functional.json')) receipt = JSON.parse(body);
          },
        };
      throw new Error(`Unexpected import: ${name}`);
    },
    __filename: '/synthetic/credential-scenario.js',
    process: scenarioProcess,
    console: { log: (message) => logs.push(message) },
  });
  assert.equal(browserClosed, true);
  assert.equal(contexts.length, 15);
  assert.ok(contexts.every((context) => context.closed));
  return { submissions, navigations, logs, receipt, exitCode: scenarioProcess.exitCode };
}

test('credential browser submits all 15 pairs through the login form after transient setup failure', async () => {
  const result = await executeCredentialScenario({ retrySetup: true });
  assert.equal(result.exitCode, undefined, result.logs.filter((message) => message.includes('ERROR:')).join('\n'));
  assert.equal(result.submissions.length, 15);
  assert.equal(result.navigations.length, 31);
  assert.equal(result.receipt.passed, true);
  assert.equal(result.receipt.attempts.length, 15);
  assert.ok(result.receipt.attempts.every((attempt) => attempt.passed));
  assert.equal(result.receipt.attempts[0].sessionClosed, true);
  assert.equal(result.submissions[0].user, 'admin');
  assert.equal(result.submissions[0].password, 'password');
  assert.equal(result.submissions[14].password, 'pass');
  assert.ok(result.logs.includes('    Credentials submitted: 15'));
  assert.ok(result.logs.every((message) => !message.includes('ERROR:')));
});

test('credential browser rejects wrong-content setup instead of claiming attack coverage', async () => {
  const result = await executeCredentialScenario({ missingForm: true });
  assert.equal(result.exitCode, 1);
  assert.equal(result.submissions.length, 0);
  assert.ok(result.logs.includes('    Credentials submitted: 0'));
});

test('credential browser receipt rejects native page errors despite completed submissions', async () => {
  const result = await executeCredentialScenario({ browserError: true });
  assert.equal(result.submissions.length, 15);
  assert.equal(result.receipt.passed, false);
  assert.ok(result.receipt.browserErrors.length > 0);
});
