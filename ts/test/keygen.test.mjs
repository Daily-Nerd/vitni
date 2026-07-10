/**
 * keygen command tests. STRICT TDD: written before the implementation.
 * Cross-impl anchor: RFC 8032 §7.1 TEST 1.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { dispatch } = await import('../dist/cli.js');

const RFC_SEED_B64 = 'nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=';
const RFC_PUB_X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const SEED_B = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA='; // sign vector's seed

const RECEIPT = {
  v: 'vitni/0.2', binding: 'mcp', action_ref: null, performer_id: 'srv-ed',
  requester_id: null, method: 'mcp:echo',
  inputs_hash: 'uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA',
  outputs_hash: 'uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA',
  cost: { tokens: '10', usd_micros: '0', wall_ms: '3', rail_ref: null },
  status: 'OK', reason: null, parent_receipt_hash: null,
  log_policy: 'best_effort', ts: '2026-05-28T00:00:00Z',
  nonce: 'uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ',
};

const kg = (raw) => JSON.parse(dispatch('keygen', raw));

test('keygen derives RFC 8032 TEST 1 public key from seed', () => {
  const out = kg(`{"seed_b64":"${RFC_SEED_B64}"}`);
  assert.deepStrictEqual(out.jwk, {
    alg: 'EdDSA', crv: 'Ed25519', kty: 'OKP', status: 'active', x: RFC_PUB_X,
  });
  assert.equal(out.private_key_b64, RFC_SEED_B64);
});

test('keygen accepts unpadded seed (flexible base64)', () => {
  const out = kg(`{"seed_b64":"${RFC_SEED_B64.replace(/=+$/, '')}"}`);
  assert.equal(out.jwk.x, RFC_PUB_X);
});

test('keygen error cases', () => {
  assert.deepStrictEqual(kg('{"seed_b64":""}'), { error: 'invalid_seed' },
    'present-but-empty seed must error, never generate');
  assert.deepStrictEqual(kg('{"seed_b64":"AQIDBAUGBwgJCgsMDQ4PEA=="}'), { error: 'invalid_seed' },
    'wrong length (16 bytes)');
  assert.deepStrictEqual(kg('{"seed_b64":"!!!not-base64!!!"}'), { error: 'invalid_seed' });
  assert.deepStrictEqual(kg('{"seed_b64":null}'), { error: 'invalid_seed' });
  assert.deepStrictEqual(kg('{"seed_b64":123}'), { error: 'invalid_seed' },
    'non-string seed value');
  assert.deepStrictEqual(kg(`{"seed_b64":"${RFC_SEED_B64}","kid":"x"}`), { error: 'invalid_input' },
    'unknown top-level key');
  assert.deepStrictEqual(kg('[1,2]'), { error: 'invalid_input' });
  assert.deepStrictEqual(kg('null'), { error: 'invalid_input' });
});

test('keygen random path: distinct keys, self-consistent derivation', () => {
  const a = kg('{}');
  const b = kg('{}');
  assert.notEqual(a.private_key_b64, b.private_key_b64);
  assert.notEqual(a.jwk.x, b.jwk.x);
  const rederived = kg(`{"seed_b64":"${a.private_key_b64}"}`);
  assert.equal(rederived.jwk.x, a.jwk.x, 're-derive from emitted seed must match');
});

function signWith(seedB64) {
  const out = JSON.parse(dispatch('sign', JSON.stringify({
    receipt: RECEIPT, kid: 'ed-1', private_key_b64: seedB64,
  })));
  assert.ok(out.signed_receipt, `sign failed: ${JSON.stringify(out)}`);
  return out.signed_receipt;
}

function verifyAgainst(signed, jwk) {
  return JSON.parse(dispatch('verify', JSON.stringify({
    signed_receipt: signed, keys: { 'srv-ed': { 'ed-1': jwk } },
  })));
}

test('keygen round-trip: keygen → sign → verify with emitted jwk', () => {
  const out = kg(`{"seed_b64":"${RFC_SEED_B64}"}`);
  const res = verifyAgainst(signWith(RFC_SEED_B64), out.jwk);
  assert.deepStrictEqual(res, { valid: true, reason: 'ok' });
});

test('keygen negative binding: jwk from seed A rejects signature from seed B', () => {
  const out = kg(`{"seed_b64":"${RFC_SEED_B64}"}`);
  const res = verifyAgainst(signWith(SEED_B), out.jwk);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'bad_signature');
});
