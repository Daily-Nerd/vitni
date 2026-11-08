import test from 'node:test';
import assert from 'node:assert/strict';
import { vectorStdin } from './vector-stdin.mjs';

test('vectorStdin: input is serialized', () => {
  assert.deepEqual(vectorStdin({ input: { a: 1 } }), Buffer.from('{"a":1}'));
});
test('vectorStdin: input_raw is verbatim (duplicate keys survive)', () => {
  assert.deepEqual(vectorStdin({ input_raw: '{"a":1,"a":2}' }), Buffer.from('{"a":1,"a":2}'));
});
test('vectorStdin: present-but-empty is empty stdin, not absent', () => {
  assert.deepEqual(vectorStdin({ input_raw: '' }), Buffer.alloc(0));
  assert.deepEqual(vectorStdin({ input_raw_b64: '' }), Buffer.alloc(0));
});
test('vectorStdin: input_raw_b64 carries bytes a JS string cannot', () => {
  assert.deepEqual(vectorStdin({ input_raw_b64: '/w==' }), Buffer.from([0xff]));
  assert.deepEqual(vectorStdin({ input_raw_b64: '77u/e30=' }), Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
});
test('vectorStdin: exactly one form is required', () => {
  assert.throws(() => vectorStdin({ name: 'none' }), /exactly one/);
  assert.throws(() => vectorStdin({ name: 'two', input: {}, input_raw: '' }), /exactly one/);
  assert.throws(() => vectorStdin({ name: 'two', input_raw: '', input_raw_b64: '' }), /exactly one/);
});
