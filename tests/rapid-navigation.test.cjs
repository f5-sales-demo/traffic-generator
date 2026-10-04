const assert = require('node:assert/strict');
const test = require('node:test');
const { validOutcome } = require('../scripts/rapid_navigation.cjs');

test('wrong rendered content, failed route and unexpected statuses fail navigation', () => {
  const expected = { statuses: [200], contentType: 'application/json' };
  const valid = { status: 200, contentType: 'application/json', urlMatches: true, contentMatches: true };
  assert.equal(validOutcome(expected, valid), true);
  for (const changed of [
    { status: 500 },
    { contentMatches: false },
    { urlMatches: false },
    { contentType: 'text/html' },
  ])
    assert.equal(validOutcome(expected, { ...valid, ...changed }), false);
});

test('negative endpoints accept only their declared application outcome', () => {
  const expected = { statuses: [405] };
  assert.equal(validOutcome(expected, { status: 405, urlMatches: true, contentMatches: true }), true);
  assert.equal(validOutcome(expected, { status: 404, urlMatches: true, contentMatches: true }), false);
});

test('a previous block document cannot establish a newly requested SPA route action', async () => {
  const { verifyNavigation } = require('../scripts/rapid_navigation.cjs');
  const page = { url: () => 'https://example.com/juice-shop/#/login', screenshot: async () => {} };
  const response = { status: () => 403, url: () => 'https://example.com/juice-shop/' };
  await assert.rejects(
    verifyNavigation(page, response, '/juice-shop/#/login', 0, '/tmp'),
    /blocked document cannot execute SPA route/,
  );
});

test('a fresh blocked document records the attempted route with its own response', async () => {
  const { verifyNavigation } = require('../scripts/rapid_navigation.cjs');
  const page = { url: () => 'https://example.com/juice-shop/#/login', screenshot: async () => {} };
  const response = { status: () => 403, url: () => 'https://example.com/juice-shop/' };
  const result = await verifyNavigation(page, response, '/juice-shop/#/login', 0, '/tmp', true);
  assert.equal(result.performed, true);
  assert.equal(result.mitigated, true);
  assert.equal(result.fresh_document_response, true);
});
