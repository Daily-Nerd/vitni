/**
 * CLI dispatch — covered in-process (main() reads stdin/argv and cannot be
 * unit-tested; dispatch() is the pure command router).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { vectorStdin } from './vector-stdin.mjs';

const DIST = new URL('../dist', import.meta.url).pathname;
const { dispatch, main, writeFatal } = await import(`${DIST}/cli.js`);

const parse = (s) => JSON.parse(s);

test('dispatch: invalid JSON', () => {
  assert.deepEqual(parse(dispatch('jcs', '{not json')), { error: 'invalid_input' });
});
test('dispatch: unknown command', () => {
  assert.deepEqual(parse(dispatch('nope', '{}')), { error: 'unsupported_command' });
});
test('dispatch: duplicate key rejected for jcs', () => {
  assert.deepEqual(parse(dispatch('jcs', '{"value":{"a":1,"a":2}}')), { error: 'invalid_input' });
});
test('dispatch: surrogate escapes at the JCS-canonicalizing commands', () => {
  const bad = ['"\\ud800"', '"\\uD800"', '"\\uDC00"', '"\\uD800A"', '"\\uD800\\ud800"', '"\\ude00\\ud83d"'];
  for (const v of bad) {
    assert.deepEqual(parse(dispatch('jcs', `{"value":${v}}`)), { error: 'invalid_input' }, v);
    assert.deepEqual(parse(dispatch('receipt-id', `{"receipt":{"x":${v}}}`)), { error: 'invalid_input' }, v);
    assert.deepEqual(parse(dispatch('cost-canon', `{"cost":{"rail_ref":${v}}}`)), { error: 'invalid_input' }, v);
  }
  // a well-formed pair escape in either case canonicalizes to the raw character
  const want = { canonical_hex: Buffer.from('"\u{1F600}"').toString('hex'), byte_len: 6 };
  assert.deepEqual(parse(dispatch('jcs', '{"value":"\\ud83d\\ude00"}')), want);
  assert.deepEqual(parse(dispatch('jcs', '{"value":"\\uD83D\\uDE00"}')), want);
});
test('dispatch: every command routes and produces output', () => {
  const cases = {
    jcs: '{"value":{"b":1,"a":2}}',
    hashstring: '{"algo":"sha2-256","digest_hex":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}',
    digest: '{"bytes_b64":"aGVsbG8="}',
    'receipt-id': '{"receipt":{"v":"vitni/0.2","binding":"mcp"}}',
    'sse-outputs-hash': '{"mode":"sse","raw_b64":"ZGF0YTogaGVsbG8KCg=="}',
    'cost-canon': '{"cost":{"tokens":"1","usd_micros":"0","wall_ms":"0","rail_ref":null}}',
    verify: '{"signed_receipt":"a.b.c","keys":{},"policy":null}',
    'verify-chain': '{"receipts":[],"keys":{},"policy":null}',
    'a2a-artifact-hash': '{"artifact":{"parts":[{"kind":"text","text":"hi"}]}}',
    sign: '{"receipt":{"v":"vitni/0.2","binding":"mcp","action_ref":null,"performer_id":"srv","requester_id":null,"method":"mcp:x","inputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","outputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","cost":{"tokens":"10","usd_micros":"0","wall_ms":"3","rail_ref":null},"status":"OK","reason":null,"parent_receipt_hash":null,"log_policy":"best_effort","ts":"2026-05-28T00:00:00Z","nonce":"uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ"},"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}',
  };
  for (const [cmd, raw] of Object.entries(cases)) {
    const out = dispatch(cmd, raw);
    assert.ok(out.length > 0, `${cmd} produced no output`);
    assert.doesNotThrow(() => JSON.parse(out), `${cmd} output not JSON`);
  }
});
test('dispatch: verify returns a verdict object, not a throw', () => {
  const out = parse(dispatch('verify', '{"signed_receipt":"a.b.c","keys":{},"policy":null}'));
  assert.equal(out.valid, false); // malformed JWS -> {valid:false, reason:"malformed"}
});
test('dispatch: a non-string raw_b64 is invalid_input, validated before the command runs', () => {
  assert.deepEqual(parse(dispatch('sse-outputs-hash', '{"mode":"sse","raw_b64":123}')), { error: 'invalid_input' });
});
test('dispatch: internal_error when a command throws', () => {
  // The command table is injectable: validation passes, then the injected
  // command throws, which is the only way to reach the last-resort catch.
  const throwing = { digest: () => { throw new Error('boom'); } };
  assert.deepEqual(parse(dispatch('digest', '{"bytes_b64":"aGVsbG8="}', throwing)), { error: 'internal_error' });
});

test('main: missing command', async () => {
  let out = '';
  await main(['node', 'cli'], async () => '', (s) => { out += s; });
  assert.deepEqual(JSON.parse(out), { error: 'missing_command' });
});
test('main: stdin read error', async () => {
  let out = '';
  await main(['node', 'cli', 'jcs'], async () => { throw new Error('pipe'); }, (s) => { out += s; });
  assert.deepEqual(JSON.parse(out), { error: 'stdin_read_error' });
});
test('main: happy path writes the command output', async () => {
  let out = '';
  await main(['node', 'cli', 'jcs'], async () => '{"value":{"a":1}}', (s) => { out += s; });
  assert.ok(JSON.parse(out).canonical_hex);
});
test('writeFatal emits internal_error', () => {
  const orig = process.stdout.write;
  let out = '';
  process.stdout.write = (s) => { out += s; return true; };
  try { writeFatal(); } finally { process.stdout.write = orig; }
  assert.deepEqual(JSON.parse(out), { error: 'internal_error' });
});

test('dispatch: unparseable stdin -> invalid_input (matches Go)', () => {
  assert.equal(dispatch('jcs', ')('), '{"error":"invalid_input"}');
});

test('dispatch: unknown command -> unsupported_command (matches Go)', () => {
  assert.equal(dispatch('not-a-command', '{}'), '{"error":"unsupported_command"}');
});

test('dispatch: non-finite number input -> invalid_input, never canonical null', () => {
  assert.equal(dispatch('jcs', '{"value":{"n":1e400}}'), '{"error":"invalid_input"}');
  assert.equal(dispatch('jcs', '{"value":{"a":[1,1e309]}}'), '{"error":"invalid_input"}');
});

// Every conformance vector, whatever its stdin form (input, input_raw,
// input_raw_b64), through the full CLI pipeline: exactly the bytes the vector
// pins go in, the printed line is compared with the anchor. There is no hand
// list, so a new vector cannot be silently untested.
const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../conformance/vectors');
const allVectors = readdirSync(VECTORS_DIR)
  .filter((f) => f.endsWith('.json') && !f.startsWith('_'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(VECTORS_DIR, f), 'utf8')));
assert.ok(allVectors.length > 100, 'vector directory scan found too few vectors');

for (const v of allVectors) {
  test(`dispatch vector: ${v.name}`, () => {
    const out = parse(dispatch(v.command, vectorStdin(v)));
    if (v.anchor === undefined) {
      assert.ok(!('error' in out), `${v.name}: unanchored vector must not error, got ${JSON.stringify(out)}`);
      return;
    }
    for (const [k, expected] of Object.entries(v.anchor)) {
      assert.deepStrictEqual(out[k], expected, `${v.name}: field ${k}`);
    }
  });
}

// D8: the command resolves before stdin is parsed.
test('dispatch: unknown command wins over any stdin', () => {
  for (const stdin of [')(', '', '[]', '{"a":1e400}', Buffer.from([0xff])]) {
    assert.equal(dispatch('not-a-command', stdin), '{"error":"unsupported_command"}');
  }
});

// Depth at the stdin edge: the top-level object is depth 1, so {"value": <127
// arrays>} is exactly 128 and one more array is 129. No host limit is relied on.
test('dispatch: stdin depth 128 accepted, 129 invalid_input', () => {
  const nest = (n) => `{"value":${'['.repeat(n)}${']'.repeat(n)}}`;
  assert.ok(!dispatch('jcs', nest(127)).includes('error'));
  assert.equal(dispatch('jcs', nest(128)), '{"error":"invalid_input"}');
  assert.equal(dispatch('jcs', nest(10000)), '{"error":"invalid_input"}');
});

// stdin is bytes: invalid UTF-8 must not be repaired into U+FFFD and answered.
test('dispatch: invalid UTF-8 bytes are invalid_input, never U+FFFD', () => {
  const bad = Buffer.concat([Buffer.from('{"value":{"a":"'), Buffer.from([0xff]), Buffer.from('"}}')]);
  assert.equal(dispatch('jcs', bad), '{"error":"invalid_input"}');
});

test('main: stdin bytes reach dispatch undecoded', async () => {
  let out = '';
  await main(['node', 'cli', 'jcs'], async () => Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), (s) => { out += s; });
  assert.equal(out, '{"error":"invalid_input"}\n');
});

// R0.12: no stdin reaches internal_error. For every command and every way the
// stdin itself can be wrong (the mutation matrix below), the answer is exactly
// one JSON object on one line and never the catch-all. A command bug that
// throws on input shows up here as `internal_error`.
const BASELINES = {
  jcs: '{"value":{"b":1,"a":2}}',
  hashstring: '{"algo":"sha2-256","digest_hex":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}',
  digest: '{"bytes_b64":"aGVsbG8="}',
  'receipt-id': '{"receipt":{"v":"vitni/0.2","binding":"mcp"}}',
  'sse-outputs-hash': '{"mode":"sse","raw_b64":"ZGF0YTogaGVsbG8KCg=="}',
  'cost-canon': '{"cost":{"tokens":"1","usd_micros":"0","wall_ms":"0","rail_ref":null}}',
  verify: '{"signed_receipt":"a.b.c","keys":{},"policy":null}',
  'verify-chain': '{"receipts":[],"keys":{},"policy":null}',
  'a2a-artifact-hash': '{"artifact":{"parts":[{"kind":"text","text":"hi"}]}}',
  sign: '{"receipt":{"v":"vitni/0.2"},"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}',
  keygen: '{}',
};
// Add one member to the baseline object by replacing its closing brace.
const withMember = (base, member) => Buffer.concat([
  Buffer.from(base.slice(0, -1) + ',"zz":'), member, Buffer.from('}'),
]);
const MUTATIONS = {
  baseline: (b) => Buffer.from(b),
  bom: (b) => Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(b)]),
  'invalid utf-8': (b) => withMember(b, Buffer.concat([Buffer.from('"'), Buffer.from([0xff]), Buffer.from('"')])),
  'lone surrogate escape': (b) => withMember(b, Buffer.from('"\\ud800"')),
  'lone low surrogate escape': (b) => withMember(b, Buffer.from('"\\udc00"')),
  'non-finite number': (b) => withMember(b, Buffer.from('1e400')),
  array: () => Buffer.from('[]'),
  null: () => Buffer.from('null'),
  string: () => Buffer.from('"x"'),
  empty: () => Buffer.alloc(0),
  'trailing garbage': (b) => Buffer.from(b + ' x'),
  'nul suffix': (b) => Buffer.concat([Buffer.from(b), Buffer.from([0])]),
  'depth 129': (b) => withMember(b, Buffer.from('['.repeat(128) + ']'.repeat(128))),
  'depth 100000': (b) => withMember(b, Buffer.from('['.repeat(100000) + ']'.repeat(100000))),
};

assert.deepEqual(Object.keys(BASELINES).sort(), [
  'a2a-artifact-hash', 'cost-canon', 'digest', 'hashstring', 'jcs', 'keygen', 'receipt-id',
  'sign', 'sse-outputs-hash', 'verify', 'verify-chain',
], 'the property test must cover every command');

for (const [command, base] of Object.entries(BASELINES)) {
  for (const [label, mutate] of Object.entries(MUTATIONS)) {
    test(`R0.12 ${command} / ${label}: one JSON line, never internal_error`, () => {
      const out = dispatch(command, mutate(base));
      assert.ok(!out.includes('\n'), 'output must be a single line');
      const parsed = JSON.parse(out);
      assert.ok(parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed));
      assert.notEqual(parsed.error, 'internal_error');
      assert.notEqual(parsed.error, 'jcs_output_error');
    });
  }
}
