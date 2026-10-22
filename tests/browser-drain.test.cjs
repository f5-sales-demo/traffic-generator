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

test('nested browser headers accept only opaque owned markers', () => {
  const { childHeaders } = require('../scripts/browser_requests.cjs');
  assert.deepEqual(childHeaders(''), {});
  assert.deepEqual(childHeaders('child-opaque'), { 'X-TGen-Child': 'child-opaque' });
  assert.throws(() => childHeaders('../foreign'));
});

test('native browser sockets close normally before browser teardown', async () => {
  const { installSocketDrain, closeSockets } = require('../scripts/browser_requests.cjs');
  const Original = global.WebSocket;
  const sockets = [];
  class NativeSocket extends EventEmitter {
    constructor() {
      super();
      this.readyState = 1;
      sockets.push(this);
    }
    addEventListener(event, callback) {
      this.on(event, callback);
    }
    close(code) {
      this.code = code;
      this.readyState = 3;
      this.emit('close', { code });
    }
  }
  global.WebSocket = NativeSocket;
  const page = { addInitScript: async (fn) => fn(), evaluate: async (fn) => fn() };
  try {
    await installSocketDrain(page);
    new global.WebSocket('wss://www.example.test/juice-shop/socket.io/');
    await closeSockets(page);
    assert.equal(sockets[0].code, 1000);
    assert.equal(sockets[0].readyState, 3);
  } finally {
    global.WebSocket = Original;
    delete global.__tgenSockets;
  }
});

test('teardown waits for outstanding native polling and rejects transport failures', async () => {
  const { finishBrowserRequests } = require('../scripts/browser_requests.cjs');
  const page = new EventEmitter();
  const commands = [];
  page.evaluate = async () => {};
  page.context = () => ({ newCDPSession: async () => ({ send: async (...args) => commands.push(args) }) });
  const state = observeRequests(page);
  const polling = { url: () => 'https://www.example.test/juice-shop/socket.io/?transport=polling&sid=synthetic' };
  page.emit('request', polling);
  assert.equal(state.polling.size, 1);
  await settleRequests(state, 50);
  await assert.rejects(settleRequests(state, 1, 1, true));
  setTimeout(() => page.emit('requestfinished', polling), 10);
  await finishBrowserRequests(page, state, 100);
  assert.deepEqual(commands, [['Emulation.setScriptExecutionDisabled', { value: true }]]);
  assert.equal(state.polling.size, 0);
  page.emit('request', polling);
  page.emit('requestfailed', polling);
  await assert.rejects(finishBrowserRequests(page, state, 100), /transport/);
});
