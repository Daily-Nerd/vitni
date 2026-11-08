/**
 * validateInput: the one place that types the members of every command's stdin.
 * Member names are exact (JSON.parse never matched case-insensitively, but this
 * table is what keeps Go and TS agreeing on which members are required and what
 * type they have). A required member that is absent or null, or any member of
 * the wrong JSON type, makes the input invalid; the CLI reports invalid_input.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { validateInput } = await import(`${DIST}/commands/schema.js`);

const table = [
  // [command, input, valid, label]
  ['jcs', { value: 1 }, true, 'value present'],
  ['jcs', { value: null }, true, 'null is a value for jcs'],
  ['jcs', {}, false, 'value absent'],
  ['jcs', { VALUE: 1 }, false, 'name differs in case'],
  ['hashstring', { algo: 'sha2-256', digest_hex: 'ab' }, true, 'both strings'],
  ['hashstring', { digest_hex: 'ab' }, false, 'algo absent'],
  ['hashstring', { algo: 1, digest_hex: 'ab' }, false, 'algo number'],
  ['hashstring', { algo: 'sha2-256' }, false, 'digest_hex absent'],
  ['hashstring', { algo: 'sha2-256', digest_hex: null }, false, 'digest_hex null'],
  ['digest', { bytes_b64: '' }, true, 'empty string is present'],
  ['digest', {}, false, 'bytes_b64 absent'],
  ['digest', { bytes_b64: null }, false, 'bytes_b64 null'],
  ['digest', { bytes_b64: 5 }, false, 'bytes_b64 number'],
  ['receipt-id', { receipt: {} }, true, 'receipt object'],
  ['receipt-id', { receipt: [] }, false, 'receipt array'],
  ['receipt-id', { receipt: 5 }, false, 'receipt number'],
  ['receipt-id', {}, false, 'receipt absent'],
  ['sse-outputs-hash', { raw_b64: '', mode: 'sse' }, true, 'both strings'],
  ['sse-outputs-hash', { raw_b64: '' }, false, 'mode absent'],
  ['sse-outputs-hash', { mode: 'sse' }, false, 'raw_b64 absent'],
  ['sse-outputs-hash', { raw_b64: 5, mode: 'sse' }, false, 'raw_b64 number'],
  ['cost-canon', { cost: {} }, true, 'cost object'],
  ['cost-canon', { cost: [] }, false, 'cost array'],
  ['cost-canon', { cost: 'x' }, false, 'cost string'],
  ['cost-canon', {}, false, 'cost absent'],
  ['a2a-artifact-hash', { artifact: { parts: [] } }, true, 'empty parts'],
  ['a2a-artifact-hash', { artifact: {} }, false, 'parts absent'],
  ['a2a-artifact-hash', { artifact: [] }, false, 'artifact array'],
  ['a2a-artifact-hash', {}, false, 'artifact absent'],
  ['a2a-artifact-hash', { artifact: { parts: 'x' } }, false, 'parts string'],
  ['a2a-artifact-hash', { artifact: { parts: [5] } }, false, 'part number'],
  ['a2a-artifact-hash', { artifact: { parts: [{ kind: 5 }] } }, false, 'kind number'],
  ['a2a-artifact-hash', { artifact: { parts: [{}] } }, true, 'kind absent is judged by the command'],
  ['a2a-artifact-hash', { artifact: { parts: [{ kind: 'file', file: 'x' }] } }, false, 'file string'],
  ['a2a-artifact-hash', { artifact: { parts: [{ kind: 'file', file: null }] } }, true, 'file null'],
  ['a2a-artifact-hash', { artifact: { parts: [{ kind: 'file', file: { bytes: 5 } }] } }, false, 'bytes number'],
  ['a2a-artifact-hash', { artifact: { parts: [{ kind: 'file', file: { uri: 'u', name: null } }] } }, true, 'name null'],
  ['sign', { receipt: {} }, true, 'kid and key are judged by the command'],
  ['sign', { receipt: {}, kid: null, private_key_b64: null }, true, 'null kid and key'],
  ['sign', { receipt: 'x' }, false, 'receipt string'],
  ['sign', {}, false, 'receipt absent'],
  ['sign', { receipt: {}, kid: 5 }, false, 'kid number'],
  ['sign', { receipt: {}, private_key_b64: 5 }, false, 'private_key_b64 number'],
  ['keygen', {}, true, 'no members'],
  ['keygen', { seed_b64: 5 }, true, 'seed_b64 is judged by the command (invalid_seed)'],
  ['verify', {}, true, 'everything optional'],
  ['verify', { signed_receipt: 5 }, false, 'signed_receipt number'],
  ['verify', { signed_receipt: null, keys: null, policy: null }, true, 'nulls'],
  ['verify', { keys: [] }, false, 'keys array'],
  ['verify', { keys: { p: [] } }, false, 'performer array'],
  ['verify', { keys: { p: null } }, true, 'performer null'],
  ['verify', { keys: { p: { k: 'x' } } }, false, 'entry string'],
  ['verify', { keys: { p: { k: null } } }, true, 'entry null'],
  ['verify', { keys: { p: { k: { x: 5 } } } }, false, 'x number'],
  ['verify', { keys: { p: { k: { alg: 5 } } } }, false, 'alg number'],
  ['verify', { keys: { p: { k: { kty: 5 } } } }, false, 'kty number'],
  ['verify', { keys: { p: { k: { status: 5 } } } }, false, 'status number'],
  ['verify', { keys: { p: { k: { x: null, rpId: 5 } } } }, true, 'null member and unknown member'],
  ['verify', { keys: { other: { k: { x: 5 } }, p: { k: {} } } }, false, 'whole tree: unrelated entry'],
  ['verify', { policy: [] }, false, 'policy array'],
  ['verify', { policy: { expected_binding: 5 } }, false, 'expected_binding number'],
  ['verify', { policy: { expected_method: 5 } }, false, 'expected_method number'],
  ['verify', { policy: { expected_method: null, extra: 5 } }, true, 'null policy member, unknown member'],
  ['verify', { Signed_Receipt: 5 }, true, 'a name differing in case is an unknown member'],
  ['verify-chain', {}, true, 'everything optional'],
  ['verify-chain', { receipts: 'x' }, false, 'receipts string'],
  ['verify-chain', { receipts: [5] }, false, 'receipt number'],
  ['verify-chain', { receipts: null }, true, 'receipts null'],
  ['verify-chain', { receipts: ['a'], keys: { p: { k: { x: 5 } } } }, false, 'keys typed like verify'],
  ['verify-chain', { receipts: [], policy: { expected_binding: 5 } }, false, 'policy typed like verify'],
];

for (const [command, input, valid, label] of table) {
  test(`validateInput ${command}: ${label}`, () => {
    assert.equal(validateInput(command, input), valid);
  });
}
