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
