const assert = require('node:assert/strict');
const test = require('node:test');

const { classifyPopulationResult, sameScriptUrl } = require('../suites/csd-detection/population-result.cjs');

const session = (scriptState, overrides = {}) => ({
  completed: true,
  sensor: true,
  twoBeacon: true,
  scriptState,
  ...overrides,
});

test('loaded expectation accepts only an all-loaded population', () => {
  const result = classifyPopulationResult('loaded', [session('loaded'), session('loaded')]);
  assert.equal(result.passed, true);
  assert.equal(result.classification, 'loaded');
  assert.deepEqual(result.counts, { total: 2, completed: 2, loaded: 2, blocked: 0, unknown: 0 });
});

test('blocked expectation accepts only an all-blocked population', () => {
  const result = classifyPopulationResult('blocked', [session('blocked'), session('blocked')]);
  assert.equal(result.passed, true);
  assert.equal(result.classification, 'blocked');
});

test('mixed outcomes fail either expectation', () => {
  const sessions = [session('loaded'), session('blocked')];
  assert.equal(classifyPopulationResult('loaded', sessions).passed, false);
  assert.equal(classifyPopulationResult('blocked', sessions).passed, false);
  assert.equal(classifyPopulationResult('loaded', sessions).classification, 'mixed');
});

test('missing script evidence fails closed', () => {
  const result = classifyPopulationResult('loaded', [session('unknown')]);
  assert.equal(result.passed, false);
  assert.equal(result.classification, 'unknown');
});

test('incomplete sessions are not silently discarded', () => {
  const result = classifyPopulationResult('loaded', [session('loaded'), session('unknown', { completed: false })]);
  assert.equal(result.passed, false);
  assert.equal(result.counts.completed, 1);
});

test('invalid expectations are rejected', () => {
  assert.throws(() => classifyPopulationResult('maybe', []), /EXPECT_SCRIPT/);
});

test('script URL matching is exact and tolerates URL normalization', () => {
  const expected = 'http://cdn.example.test/csd-demo/checkout.js';
  assert.equal(sameScriptUrl(expected, expected), true);
  assert.equal(sameScriptUrl(`${expected}?cache=1`, expected), false);
  assert.equal(sameScriptUrl('http://other.example.test/csd-demo/checkout.js', expected), false);
});
