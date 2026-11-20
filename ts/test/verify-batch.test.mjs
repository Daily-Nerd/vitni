/**
 * verify-batch: many independent verify questions in one call. Counterpart of
 * go/cmd/vitni-verify/batch_test.go; both pin the same contract.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIST = new URL('../dist', import.meta.url).pathname;
const { dispatch } = await import(`${DIST}/cli.js`);
const { MAX_BATCH_QUESTIONS } = await import(`${DIST}/commands/verify-batch.js`);

const batchOf = (...elements) => `{"questions":[${elements.join(',')}]}`;
const deep = (n) => '['.repeat(n) + ']'.repeat(n);
const INVALID = '{"error":"invalid_input"}';
const MALFORMED = '{"reason":"malformed","valid":false}';

test('verify-batch: result i answers question i alone, a bad element touches no other', () => {
  const out = dispatch('verify-batch', batchOf(
    '{}',
    '5',
    'null',
    '[]',
    '{"signed_receipt":5}',
    '{"keys":[]}',
    '{"signed_receipt":"a.b.c","keys":{}}',
  ));
  assert.equal(out, `{"results":[${[MALFORMED, INVALID, INVALID, INVALID, INVALID, INVALID, MALFORMED].join(',')}]}`);
});

test('verify-batch: the empty list answers an empty list', () => {
  assert.equal(dispatch('verify-batch', batchOf()), '{"results":[]}');
});

test('verify-batch: the batch itself must be {"questions":[...]}', () => {
  for (const stdin of ['{}', '{"questions":null}', '{"questions":{}}', '{"questions":"x"}', '{"questions":5}',
    '{"Questions":[]}', '[]', 'null', '']) {
    assert.equal(dispatch('verify-batch', stdin), INVALID, JSON.stringify(stdin));
  }
});

test('verify-batch: the limit is 65536 questions, one more is batch_too_large', () => {
  assert.equal(MAX_BATCH_QUESTIONS, 65536);
  const build = (n) => `{"questions":[${'{},'.repeat(n).slice(0, -1)}]}`;
  const ok = JSON.parse(dispatch('verify-batch', build(MAX_BATCH_QUESTIONS)));
  assert.equal(ok.results.length, MAX_BATCH_QUESTIONS);
  assert.equal(dispatch('verify-batch', build(MAX_BATCH_QUESTIONS + 1)), '{"error":"batch_too_large"}');
});

test('verify-batch: a text fault anywhere fails the whole batch', () => {
  assert.equal(dispatch('verify-batch', batchOf('{}', '{"x":"\\ud800"}')), INVALID, 'lone surrogate');
  assert.equal(dispatch('verify-batch', batchOf('{}', '{"x":1e400}')), INVALID, 'non-finite');
  // elements sit two levels deeper than a lone verify input: depth 3 + n
  assert.equal(dispatch('verify-batch', batchOf('{}', `{"x":${deep(126)}}`)), INVALID, 'depth 129');
  assert.doesNotMatch(dispatch('verify-batch', batchOf(`{"x":${deep(125)}}`)), /error/, 'depth 128 is accepted');
  assert.doesNotMatch(dispatch('verify', `{"x":${deep(127)}}`), /error/, 'a lone verify accepts depth 128 too');
});

test('verify-batch: duplicate keys are last-wins, as for verify', () => {
  assert.equal(
    dispatch('verify-batch', '{"questions":[],"questions":[{"signed_receipt":5,"signed_receipt":null}]}'),
    `{"results":[${MALFORMED}]}`,
  );
});

test('verify-batch: one bad element in the middle never changes the others', () => {
  const alone = dispatch('verify', '{"signed_receipt":"a.b.c","keys":{},"policy":null}');
  const out = JSON.parse(dispatch('verify-batch', batchOf(
    '{"signed_receipt":"a.b.c","keys":{},"policy":null}', '7',
    '{"signed_receipt":"a.b.c","keys":{},"policy":null}',
  )));
  assert.deepEqual(out.results.map((r) => JSON.stringify(r)), [alone, INVALID, alone]);
});

// The drift guard for the shared code path: every structured verify vector,
// wrapped as a one-element batch, gives results[0] byte-identical to verify alone.
test('verify-batch: results[0] equals verify alone for every structured verify vector', () => {
  const dir = join(dirname(fileURLToPath(import.meta.url)), '../../conformance/vectors');
  let checked = 0;
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.json') && !n.startsWith('_')).sort()) {
    const v = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    if (v.command !== 'verify' || v.input === undefined) continue;
    const alone = dispatch('verify', JSON.stringify(v.input));
    assert.equal(dispatch('verify-batch', batchOf(JSON.stringify(v.input))), `{"results":[${alone}]}`, v.name);
    checked++;
  }
  assert.ok(checked >= 100, `only ${checked} verify vectors checked; the scan is vacuous`);
});
