/**
 * Duplicate-key detection (§4.1) and sign-side field/cost validation (#34).
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { hasDuplicateKeys, rejectsForDuplicateKeys } = await import(`${DIST}/commands/strict-json.js`);
const { sign } = await import(`${DIST}/commands/sign.js`);

test('hasDuplicateKeys: flat duplicate', () => {
  assert.equal(hasDuplicateKeys('{"a":1,"a":2}'), true);
});
test('hasDuplicateKeys: nested duplicate', () => {
  assert.equal(hasDuplicateKeys('{"v":{"b":1,"b":2}}'), true);
});
test('hasDuplicateKeys: duplicate inside array element', () => {
  assert.equal(hasDuplicateKeys('{"xs":[{"k":1},{"d":1,"d":2}]}'), true);
});
test('hasDuplicateKeys: no duplicates', () => {
  assert.equal(hasDuplicateKeys('{"a":1,"b":2,"c":{"d":3}}'), false);
});
test('hasDuplicateKeys: same key at different levels is not a duplicate', () => {
  assert.equal(hasDuplicateKeys('{"a":{"a":1}}'), false);
});
test('hasDuplicateKeys: keys with escapes and colons/braces in string values', () => {
  assert.equal(hasDuplicateKeys('{"a":"x:y{}","b":"\\"q\\""}'), false);
  assert.equal(hasDuplicateKeys('{"a\\n":1,"a\\n":2}'), true);
});
test('hasDuplicateKeys: all key-escape forms decode without false positives', () => {
  // \t \b \f \/ \\ \r \u — exercises every branch of the key string decoder
  assert.equal(hasDuplicateKeys('{"a\\tb\\bc\\fd\\/e\\\\f\\rg\\u0041h":1}'), false);
});
test('hasDuplicateKeys: top-level array with a duplicate inside', () => {
  assert.equal(hasDuplicateKeys('[{"a":1,"a":2}]'), true);
  assert.equal(hasDuplicateKeys('[1,2,3]'), false);
});
test('hasDuplicateKeys: primitive values (number, bool, null) are skipped', () => {
  assert.equal(hasDuplicateKeys('{"a":1,"b":true,"c":false,"d":null,"e":-3.5e2}'), false);
});
test('hasDuplicateKeys: top-level non-object values', () => {
  assert.equal(hasDuplicateKeys('"just a string"'), false);
  assert.equal(hasDuplicateKeys('42'), false);
});
test('hasDuplicateKeys: truncated fragments return false without throwing', () => {
  // the scanner does not pre-validate (JSON.parse guards that upstream); these
  // exercise the loop-fell-through returns for unterminated string/array/object.
  assert.equal(hasDuplicateKeys('{"unterminated'), false);
  assert.equal(hasDuplicateKeys('[1,2'), false);
  assert.equal(hasDuplicateKeys('{"a":1'), false);
});

const RECEIPT = {
  v: 'vitni/0.2', binding: 'mcp', action_ref: null, performer_id: 'srv',
  requester_id: null, method: 'mcp:x',
  inputs_hash: 'uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA',
  outputs_hash: 'uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA',
  cost: { tokens: '10', usd_micros: '0', wall_ms: '3', rail_ref: null },
  status: 'OK', reason: null, parent_receipt_hash: null,
  log_policy: 'best_effort', ts: '2026-05-28T00:00:00Z',
  nonce: 'uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ',
};
const KEY = { kid: 'ed-1', private_key_b64: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=' };

test('sign: unknown top-level key rejected', () => {
  assert.deepEqual(sign({ receipt: { ...RECEIPT, foo: 'x' }, ...KEY }), { error: 'invalid_input' });
});
test('sign: numeric cost magnitude rejected', () => {
  const bad = { ...RECEIPT, cost: { ...RECEIPT.cost, tokens: 10 } };
  assert.deepEqual(sign({ receipt: bad, ...KEY }), { error: 'invalid_input' });
});
test('sign: ext key is allowed (extension slot)', () => {
  const out = sign({ receipt: { ...RECEIPT, ext: { 'dev.x/foo': '1' } }, ...KEY });
  assert.ok('signed_receipt' in out);
});
test('sign: valid receipt still signs', () => {
  assert.ok('signed_receipt' in sign({ receipt: RECEIPT, ...KEY }));
});

test('rejectsForDuplicateKeys: only the three JCS commands, only with a dup', () => {
  assert.equal(rejectsForDuplicateKeys('jcs', '{"value":{"a":1,"a":2}}'), true);
  assert.equal(rejectsForDuplicateKeys('receipt-id', '{"receipt":{"v":1,"v":2}}'), true);
  assert.equal(rejectsForDuplicateKeys('cost-canon', '{"cost":{"tokens":"1","tokens":"2"}}'), true);
  assert.equal(rejectsForDuplicateKeys('jcs', '{"value":{"a":1,"b":2}}'), false);   // no dup
  assert.equal(rejectsForDuplicateKeys('digest', '{"a":1,"a":2}'), false);          // command keeps-last in Go
  assert.equal(rejectsForDuplicateKeys('verify', '{"a":1,"a":2}'), false);
});
