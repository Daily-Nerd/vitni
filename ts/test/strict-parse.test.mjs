/**
 * parseStrict: the single owner of JSON text policy in the TS impl. Same table
 * as Go's ValidateJSONText (go/strictjson_test.go).
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { parseStrict, MAX_DEPTH } = await import(`${DIST}/commands/strict-json.js`);

const deep = (n) => '['.repeat(n) + ']'.repeat(n);
const none = { rejectDuplicates: false, rejectNonFinite: false };
const dup = { rejectDuplicates: true, rejectNonFinite: false };
const nf = { rejectDuplicates: false, rejectNonFinite: true };
const both = { rejectDuplicates: true, rejectNonFinite: true };
const bytes = (s) => (typeof s === 'string' ? Buffer.from(s, 'utf8') : Buffer.from(s));

const CASES = [
  ['object', '{"a":1}', none, true],
  ['trailing whitespace', '{"a":1} \n\t', none, true],
  ['array is valid text', '[1,2]', none, true],
  ['empty', '', none, false],
  ['bom', [0xef, 0xbb, 0xbf, ...Buffer.from('{"a":1}')], none, false],
  ['invalid utf8 in string', [...Buffer.from('{"a":"'), 0xff, ...Buffer.from('"}')], none, false],
  ['overlong utf8', [...Buffer.from('{"a":"'), 0xc0, 0x80, ...Buffer.from('"}')], none, false],
  ['utf8 encoded surrogate', [...Buffer.from('{"a":"'), 0xed, 0xa0, 0x80, ...Buffer.from('"}')], none, false],
  ['lone high escape', '{"a":"\\ud800"}', none, false],
  ['lone low escape', '{"a":"\\udc00"}', none, false],
  ['lone surrogate in key', '{"\\ud800":1}', none, false],
  ['high then non-low escape', '{"a":"\\ud800\\u0041"}', none, false],
  ['low then high (reversed pair)', '{"a":"\\ude00\\ud83d"}', none, false],
  ['high at end of string', '{"a":"x\\ud800"}', none, false],
  ['valid pair escape', '{"a":"\\ud83d\\ude00"}', none, true],
  ['escaped backslash is not an escape', '{"a":"\\\\ud800"}', none, true],
  ['raw non-bmp', '{"a":"\u{1F600}"}', none, true],
  ['depth 128 ok', deep(128), none, true],
  ['depth 129 rejected', deep(129), none, false],
  ['depth 128 objects ok', '{"a":'.repeat(128) + '1' + '}'.repeat(128), none, true],
  ['depth 129 objects rejected', '{"a":'.repeat(129) + '1' + '}'.repeat(129), none, false],
  ['brackets inside string do not count', '{"a":"' + '['.repeat(500) + '"}', none, true],
  ['depth 100000 does not blow the stack', deep(100000), none, false],
  ['duplicate allowed when off', '{"a":1,"a":2}', none, true],
  ['duplicate rejected when on', '{"a":1,"a":2}', dup, false],
  ['nested duplicate rejected when on', '{"x":{"a":1,"a":2}}', dup, false],
  ['duplicate via escape rejected when on', '{"a":1,"\\u0061":2}', dup, false],
  ['same key in sibling objects is fine', '{"x":{"a":1},"y":{"a":2}}', dup, true],
  ['same key in array elements is fine', '[{"a":1},{"a":2}]', dup, true],
  ['duplicate inside array element rejected', '[{"a":1,"a":2}]', dup, false],
  ['non-finite accepted when off', '{"a":1e400}', none, true],
  ['non-finite rejected when on', '{"a":1e400}', nf, false],
  ['negative non-finite rejected when on', '{"a":-1e400}', nf, false],
  ['non-finite nested rejected when on', '{"a":[{"b":1e999}]}', both, false],
  ['underflow is finite', '{"a":1e-400}', nf, true],
  ['large finite', '{"a":1.7976931348623157e308}', nf, true],
  ['trailing garbage', '{"a":1} x', none, false],
  ['two values', '{"a":1}{"b":2}', none, false],
  ['nul suffix', [...Buffer.from('{"a":1}'), 0x00], none, false],
  ['not json', '{not json', none, false],
];

test('MAX_DEPTH is 128', () => assert.equal(MAX_DEPTH, 128));

for (const [name, input, policy, wantOk] of CASES) {
  test(`parseStrict: ${name}`, () => {
    const r = parseStrict(bytes(input), policy);
    assert.equal(r.ok, wantOk);
  });
}

test('parseStrict: returns the parsed value', () => {
  const r = parseStrict(bytes('{"a":[1,"x"]}'), none);
  assert.deepEqual(r, { ok: true, value: { a: [1, 'x'] } });
});

test('parseStrict: header duplicate keys are last-wins when allowed', () => {
  const r = parseStrict(bytes('{"kid":"zzz","kid":"ed-1"}'), none);
  assert.deepEqual(r, { ok: true, value: { kid: 'ed-1' } });
});
