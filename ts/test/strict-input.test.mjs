/**
 * TS must reject malformed input that the Go reference rejects (DESIGN.md §4.1:
 * one pinned encoding per byte source). These guard against Node's lenient
 * built-ins silently accepting out-of-alphabet / wrong-length input and
 * hashing a different octet string than a strict verifier.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { digest } = await import(`${DIST}/commands/digest.js`);
const { hashstring } = await import(`${DIST}/commands/hashstring.js`);
const { costCanon } = await import(`${DIST}/commands/cost-canon.js`);
const { sseOutputsHash } = await import(`${DIST}/commands/sse-outputs-hash.js`);
const { a2aArtifactHash } = await import(`${DIST}/commands/a2a-artifact-hash.js`);
const { decodeStdBase64, decodeHex } = await import(`${DIST}/commands/decode.js`);

test('decodeStdBase64 accepts valid standard base64 (padded and raw)', () => {
  assert.deepEqual(decodeStdBase64('aGVsbG8='), Buffer.from('hello'));
  assert.deepEqual(decodeStdBase64('aGVsbG8'), Buffer.from('hello'));
  assert.deepEqual(decodeStdBase64(''), Buffer.alloc(0));
});

test('decodeStdBase64 rejects out-of-alphabet, base64url, junk, bad length', () => {
  assert.equal(decodeStdBase64('aGVsbG8=!!!@@@'), null); // trailing junk
  assert.equal(decodeStdBase64('aGVs bG8='), null);      // whitespace
  assert.equal(decodeStdBase64('aa-_'), null);           // base64url chars
  assert.equal(decodeStdBase64('a'), null);              // impossible length (mod 4 == 1)
});

test('decodeHex rejects odd length and non-hex', () => {
  assert.deepEqual(decodeHex('abcd'), Buffer.from([0xab, 0xcd]));
  assert.equal(decodeHex('abc'), null);   // odd length (Node would truncate to 0xab)
  assert.equal(decodeHex('zz'), null);    // non-hex
});

test('digest rejects malformed base64 with invalid_input', () => {
  assert.deepEqual(digest({ bytes_b64: 'aGVsbG8=!!!@@@' }), { error: 'invalid_input' });
  assert.ok('hashstr' in digest({ bytes_b64: 'aGVsbG8=' })); // valid still works
});

test('hashstring rejects odd-length hex with invalid_input', () => {
  assert.deepEqual(hashstring({ algo: 'sha2-256', digest_hex: 'abc' }), { error: 'invalid_input' });
});

test('cost-canon rejects non-string magnitudes (number, bool, null, array, object)', () => {
  const base = { tokens: '10', usd_micros: '0', wall_ms: '3', rail_ref: null };
  for (const bad of [5, true, null, [], {}]) {
    assert.deepEqual(
      costCanon({ cost: { ...base, tokens: bad } }),
      { error: 'cost_must_be_string_int' },
      `magnitude ${JSON.stringify(bad)} must be rejected`
    );
  }
  assert.ok('canonical_hex' in costCanon({ cost: base })); // all-strings still works
});

test('sse-outputs-hash rejects malformed base64 with invalid_input', () => {
  assert.deepEqual(sseOutputsHash({ mode: 'sse', raw_b64: 'aa!!!garbage' }), { error: 'invalid_input' });
});

test('a2a inline file bytes: malformed base64 rejected with invalid_input', () => {
  const out = a2aArtifactHash({ artifact: { parts: [{ kind: 'file', file: { bytes: 'aa!!!@@@' } }] } });
  assert.deepEqual(out, { error: 'invalid_input' });
});
