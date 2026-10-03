const assert = require('node:assert/strict');
const test = require('node:test');
const { readFileSync } = require('node:fs');
const { syntheticArithmetic } = require('../scripts/synthetic_arithmetic.cjs');

test('synthetic arithmetic preserves multiplication precedence and rejects executable input', () => {
  assert.equal(syntheticArithmetic('2+3*4'), 14);
  assert.equal(syntheticArithmetic('2*3-10'), -4);
  assert.equal(syntheticArithmetic('10-2-3'), 5);
  assert.throws(() => syntheticArithmetic('process.exit()'));
});

test('browser forms dispatch through native controls without request fallbacks', () => {
  const login = readFileSync('suites/bot-simulation/01-playwright-credential-stuff.js', 'utf8');
  const forms = readFileSync('suites/bot-simulation/03-headless-form-fill.js', 'utf8');
  assert.doesNotMatch(login, /context\.request\.post/);
  assert.doesNotMatch(forms, /fetch\(/);
  assert.match(forms, /page\.click\('#registerButton'\)/);
  assert.match(forms, /page\.click\('#submitButton'\)/);
});
