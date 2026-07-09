/**
 * ext is an OPTIONAL namespaced-extensions object (design: "never affects
 * core verification"). TS receipts are plain objects, so ext must flow
 * through sign untouched and land in the signed payload.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST = join(__dirname, '../dist');

const { sign } = await import(`${DIST}/commands/sign.js`);

const receipt = {
  v: 'vitni/0.2', binding: 'local', action_ref: null,
  performer_id: 'daimon:kibukx', requester_id: null,
  method: 'local:daimon.serialize',
  inputs_hash: 'uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA',
  outputs_hash: 'uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA',
  cost: { tokens: '10', usd_micros: '0', wall_ms: '3', rail_ref: null },
  status: 'OK', reason: null, parent_receipt_hash: null,
  log_policy: 'best_effort', ts: '2026-05-28T00:00:00Z',
  nonce: 'uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ',
  ext: { 'dev.daimon/prompt_version': '3' },
};

test('sign preserves ext in the signed payload', () => {
  const out = sign({
    receipt,
    kid: 'ed-1',
    private_key_b64: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
  });
  assert.ok('signed_receipt' in out, `sign returned an error: ${JSON.stringify(out)}`);
  const payloadB64 = out.signed_receipt.split('.')[1];
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
  assert.deepEqual(payload.ext, { 'dev.daimon/prompt_version': '3' });
});
