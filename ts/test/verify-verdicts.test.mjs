/**
 * verify() called by a JS caller, not through the CLI: the CLI schema rejects a
 * non-string signed_receipt as invalid_input before verify runs, so only the
 * library boundary can reach this guard. Every other verdict is pinned by a
 * conformance vector.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { verify } = await import(`${DIST}/commands/verify.js`);

test('verify: a non-string signed_receipt is malformed at the library boundary', () => {
  const out = verify({ signed_receipt: 5, keys: {}, policy: { expected_binding: null, expected_method: null } });
  assert.deepEqual(out, { valid: false, reason: 'malformed' });
});
