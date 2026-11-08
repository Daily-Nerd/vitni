/**
 * decodeB64UrlStrict: the single base64url decoder for JWS segments and
 * registry key coordinates. Same table as Go's DecodeB64URLStrict.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { decodeB64UrlStrict } = await import(`${DIST}/commands/decode.js`);

const CASES = [
  ['empty', '', Buffer.alloc(0)],
  ['valid 5 bytes', 'aGVsbG8', Buffer.from('hello')],
  ['valid url chars', '-_8', Buffer.from([0xfb, 0xff])],
  ['padding', 'aGVsbG8=', null],
  ['std plus', 'a+8', null],
  ['std slash', 'a/8', null],
  ['space', 'aGVs bG8', null],
  ['carriage return', 'aGVs\rbG8', null],
  ['line feed', 'aGVs\nbG8', null],
  ['trailing line feed', 'aGVsbG8\n', null],
  ['length 1 mod 4', 'aGVsb', null],
  ['non-zero trailing bits', 'aGVsbG9', null],
  ['non-ascii', 'aGVsbé', null],
  ['nul byte', 'aGVs\u0000bG8', null],
];

for (const [name, input, want] of CASES) {
  test(`decodeB64UrlStrict: ${name}`, () => {
    const got = decodeB64UrlStrict(input);
    if (want === null) {
      assert.equal(got, null);
    } else {
      assert.ok(got !== null, 'expected a Buffer');
      assert.deepEqual([...got], [...want]);
    }
  });
}

// The CLI types the whole keys tree before verify runs, but `verify` is also an
// exported library function and a library caller is not typed by the CLI: an
// ES256 key without `y` is legal per RegistryJwk, and an untyped caller can pass
// any value. The decoder's string check is that caller's only boundary, so a
// coordinate that is not a string is a key-material problem (bad_signature),
// never a TypeError thrown out of verify.
const { verify } = await import(`${DIST}/commands/verify.js`);
const VECTORS = new URL('../../conformance/vectors', import.meta.url).pathname;
const { readFileSync } = await import('node:fs');
const es256 = JSON.parse(readFileSync(`${VECTORS}/verify-valid-es256.json`, 'utf8')).input;

function withKey(patch) {
  const keys = structuredClone(es256.keys);
  const [performer, kid] = Object.entries(keys)
    .flatMap(([p, byKid]) => Object.keys(byKid).filter((k) => byKid[k].alg === 'ES256').map((k) => [p, k]))[0];
  const key = { ...keys[performer][kid], ...patch };
  for (const [k, v] of Object.entries(patch)) if (v === undefined) delete key[k];
  keys[performer][kid] = key;
  return { ...es256, keys };
}

for (const [name, patch] of [
  ['y absent', { y: undefined }],
  ['x a number', { x: 1234 }],
  ['y a number', { y: 1234 }],
  ['x an object', { x: {} }],
]) {
  test(`library verify: registry coordinate ${name} is bad_signature`, () => {
    assert.deepEqual(verify(withKey(patch)), { valid: false, reason: 'bad_signature' });
  });
}

test('library verify: the unpatched ES256 key still verifies', () => {
  assert.deepEqual(verify(withKey({})), { valid: true, reason: 'ok' });
});
