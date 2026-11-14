const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { chromium } = require('playwright');
const { observeRequests, installSocketDrain, finishBrowserRequests } = require('../scripts/browser_requests.cjs');

test('completed browser workload drains native polling without cancellation or another poll', async () => {
  let polls = 0;
  let completed = 0;
  let cancelled = 0;
  let start;
  const started = new Promise((resolve) => {
    start = resolve;
  });
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end(
        '<html><body>synthetic<script>async function poll(){await fetch("/socket.io/?transport=polling&sid=synthetic").then(r=>r.text());setTimeout(poll,10)}poll();</script></body></html>',
      );
    } else if (request.url.startsWith('/socket.io/')) {
      polls++;
      start();
      response.on('close', () => {
        if (!response.writableFinished) cancelled++;
      });
      setTimeout(() => {
        response.writeHead(200, { 'Content-Type': 'text/plain' });
        response.end('native polling response');
        completed++;
      }, 2000);
    } else {
      response.writeHead(404);
      response.end();
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await installSocketDrain(page);
    const state = observeRequests(page);
    await page.goto(`http://127.0.0.1:${server.address().port}`, { waitUntil: 'domcontentloaded' });
    await started;
    assert.equal(state.polling.size, 1);
    await finishBrowserRequests(page, state, 5000);
    await browser.close();
    browser = null;
    assert.equal(state.failed.size, 0);
    assert.equal(state.polling.size, 0);
    assert.equal(polls, 1);
    assert.equal(completed, 1);
    assert.equal(cancelled, 0);
  } finally {
    if (browser) await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
