/**
 * ALGS is the single owner of {alg -> kty, crv} in the TS verifier; the
 * declared alg set derives from it, so it cannot drift from what verify accepts.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { ALGS } = await import(`${DIST}/commands/verify.js`);

test('ALGS: exactly EdDSA and ES256', () => {
  assert.deepEqual(Object.keys(ALGS).sort(), ['ES256', 'EdDSA']);
});

test('ALGS: key types per alg', () => {
  assert.deepEqual(ALGS.EdDSA, { kty: 'OKP', crv: 'Ed25519' });
  assert.deepEqual(ALGS.ES256, { kty: 'EC', crv: 'P-256' });
});
