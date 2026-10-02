import assert from 'node:assert/strict';
import test from 'node:test';
import { validateAzure } from '../suites/csd-violations/azure.mjs';

const environment = {
  SOURCE_COMMIT: 'a'.repeat(40),
  TGEN_ARTIFACT_SHA256: 'b'.repeat(64),
  TARGET_URL: 'https://www.example.test/juice-shop/',
  TGEN_AUTHORIZED_HOST: 'www.example.test',
  TGEN_RESULTS_DIR: '/tmp/private-evidence',
};
test('Azure browser requires immutable provenance and exact authorized WAAP path', () => {
  assert.equal(validateAzure(environment).pathname, '/juice-shop/');
  for (const change of [
    { SOURCE_COMMIT: 'main' },
    { TARGET_URL: 'https://outside.example.test/juice-shop/' },
    { TARGET_URL: 'http://www.example.test/juice-shop/' },
    { TARGET_URL: 'https://www.example.test/' },
    { TGEN_RESULTS_DIR: 'relative' },
  ]) {
    assert.throws(() => validateAzure({ ...environment, ...change }));
  }
});
