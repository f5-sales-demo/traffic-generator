const assert = require('node:assert/strict');
const test = require('node:test');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

const source = readFileSync('suites/bot-simulation/01-playwright-credential-stuff.js', 'utf8');

async function executeCredentialScenario({ missingForm = false, retrySetup = false } = {}) {
  const submissions = [];
  const navigations = [];
  const logs = [];
  const contexts = [];
  let browserClosed = false;
  const scenarioProcess = {
    argv: ['node', 'credential-scenario.js', 'example.invalid'],
    env: { TARGET_PROTOCOL: 'https', TGEN_INHERITED_BOUNDARY: '1' },
    pid: 12345,
    on() {},
  };
  const browser = {
    async newContext() {
      const fields = {};
      let setupAttempts = 0;
      const context = { closed: false };
      const page = {
        setDefaultTimeout() {},
        async goto(url, options) {
          assert.equal(url, 'https://example.invalid/dvwa/login.php');
          assert.equal(options.waitUntil, 'domcontentloaded');
          assert.equal(options.timeout, 30000);
          navigations.push(url);
          setupAttempts++;
          return { status: () => (retrySetup && setupAttempts === 1 ? 503 : 200) };
        },
        async $(selector) {
          assert.equal(selector, 'input[name="username"]');
          return missingForm ? null : {};
        },
        async textContent() {
          return 'Unexpected landing page';
        },
        async fill(selector, value) {
          fields[selector] = value;
        },
        async click(selector) {
          assert.equal(selector, 'input[type="submit"]');
          submissions.push({
            user: fields['input[name="username"]'],
            password: fields['input[name="password"]'],
          });
        },
        async waitForTimeout() {},
        url: () => 'https://example.invalid/dvwa/login.php',
      };
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
    require(name) {
      if (name === 'playwright') return { chromium: { launch: async () => browser } };
      if (name.endsWith('browser_requests.cjs'))
        return { observeRequests: () => ({}), settleRequests: async () => {}, childHeaders: () => ({}) };
      if (name === 'node:path') return path;
      if (name === 'node:fs') return { rmSync() {} };
      throw new Error(`Unexpected import: ${name}`);
    },
    __filename: '/synthetic/credential-scenario.js',
    process: scenarioProcess,
    console: { log: (message) => logs.push(message) },
  });
  assert.equal(browserClosed, true);
  assert.equal(contexts.length, 15);
  assert.ok(contexts.every((context) => context.closed));
  return { submissions, navigations, logs, exitCode: scenarioProcess.exitCode };
}

test('credential browser submits all 15 pairs through the login form after transient setup failure', async () => {
  const result = await executeCredentialScenario({ retrySetup: true });
  assert.equal(result.exitCode, undefined);
  assert.equal(result.submissions.length, 15);
  assert.equal(result.navigations.length, 30);
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
