const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { observeRequests, settleRequests } = require('../scripts/browser_requests.cjs');

test('browser drain observes completion and fails unresolved application requests', async () => {
  const page = new EventEmitter();
  const state = observeRequests(page);
  const request = { url: () => 'https://www.example.test/juice-shop/rest/captcha/' };
  page.emit('request', request);
  await assert.rejects(settleRequests(state, 1));
  page.emit('requestfinished', request);
  await settleRequests(state, 50);
  page.emit('request', request);
  setTimeout(() => page.emit('requestfinished', request), 10);
  await settleRequests(state, 100);
});
