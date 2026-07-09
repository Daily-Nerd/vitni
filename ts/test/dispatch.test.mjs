/**
 * CLI dispatch — covered in-process (main() reads stdin/argv and cannot be
 * unit-tested; dispatch() is the pure command router).
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const DIST = new URL('../dist', import.meta.url).pathname;
const { dispatch, main, writeFatal } = await import(`${DIST}/cli.js`);

const parse = (s) => JSON.parse(s);

test('dispatch: invalid JSON', () => {
  assert.deepEqual(parse(dispatch('jcs', '{not json')), { error: 'invalid_json' });
});
test('dispatch: unknown command', () => {
  assert.deepEqual(parse(dispatch('nope', '{}')), { error: 'unknown_command' });
});
test('dispatch: duplicate key rejected for jcs', () => {
  assert.deepEqual(parse(dispatch('jcs', '{"value":{"a":1,"a":2}}')), { error: 'invalid_input' });
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
test('dispatch: internal_error when a command throws', () => {
  // sse-outputs-hash with a non-string raw_b64 makes the decoder throw internally.
  const out = parse(dispatch('sse-outputs-hash', '{"mode":"sse","raw_b64":123}'));
  assert.ok('error' in out);
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
