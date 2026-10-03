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
