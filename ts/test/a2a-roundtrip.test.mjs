/**
 * End-to-end A2A binding test.
 *
 * Proves Vitni drops into the real @a2a-js/sdk server stack (AgentExecutor +
 * DefaultRequestHandler + InMemoryTaskStore + ExecutionEventBus) and that a receipt
 * round-trips through verification AND binds the artifact the consumer received.
 *
 * Flow:
 *   agent executor produces an artifact -> A2A vitni middleware attaches the JWS at
 *   artifact.metadata["dev.veritrail/receipt"] -> request handler returns the completed Task
 *   -> consumer pulls the artifact, extracts the JWS, verifies with §7 verify()
 *   -> consumer independently recomputes the §9 outputs_hash over the artifact parts
 *      it received and asserts equality
 *   -> tamper: alter an artifact part -> recomputed hash diverges -> rejected.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST = join(__dirname, '../dist');

const { verify } = await import(`${DIST}/commands/verify.js`);
const { a2aArtifactHash } = await import(`${DIST}/commands/a2a-artifact-hash.js`);
const { generateTestSigner, registryFromSigner } = await import(`${DIST}/mcp/vitni-middleware.js`);
const { RECEIPT_META_KEY } = await import(`${DIST}/a2a/vitni-a2a-middleware.js`);
const { runA2ARoundTrip } = await import(`${DIST}/a2a/server.js`);

function recomputeHash(parts) {
  const res = a2aArtifactHash({ artifact: { parts } });
  return res.outputs_hash;
}

test('a2a/roundtrip: receipt verifies and binds the received artifact', async () => {
  const signer = generateTestSigner();
  const { artifact, signer: usedSigner } = await runA2ARoundTrip({
    signer,
    skill: 'summarize',
    text: 'hello world',
  });

  // 1. The receipt JWS must sit at artifact.metadata[RECEIPT_META_KEY]
  assert.ok(artifact.metadata, 'artifact should carry metadata');
  const jws = artifact.metadata[RECEIPT_META_KEY];
  assert.equal(typeof jws, 'string', 'receipt JWS must be a compact string');
  assert.equal(jws.split('.').length, 3, 'receipt must be a 3-part compact JWS');

  // 2. Verify with §7 verify(), registry built from the published key.
  const keys = registryFromSigner(usedSigner);
  const v = verify({
    signed_receipt: jws,
    keys,
    policy: { expected_binding: 'a2a', expected_method: 'a2a:summarize' },
  });
  assert.deepEqual(v, { valid: true, reason: 'ok' }, 'receipt must verify OK');

  // 3. Independently recompute §9 outputs_hash over the artifact parts the CONSUMER received.
  const payload = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'));
  const recomputed = recomputeHash(artifact.parts);
  assert.equal(
    recomputed,
    payload.outputs_hash,
    'recomputed §9 outputs_hash must match the receipt — proves the receipt binds the artifact'
  );
});

test('a2a/roundtrip: tampering an artifact part is caught', async () => {
  const signer = generateTestSigner();
  const { artifact, signer: usedSigner } = await runA2ARoundTrip({
    signer,
    skill: 'summarize',
    text: 'hello world',
  });

  const jws = artifact.metadata[RECEIPT_META_KEY];
  const payload = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'));

  // The signature still verifies (real signature)...
  const keys = registryFromSigner(usedSigner);
  const v = verify({
    signed_receipt: jws,
    keys,
    policy: { expected_binding: 'a2a', expected_method: 'a2a:summarize' },
  });
  assert.deepEqual(v, { valid: true, reason: 'ok' });

  // ...but tamper an artifact part the consumer validates against.
  const tamperedParts = JSON.parse(JSON.stringify(artifact.parts));
  // flip the text content of the first text part
  for (const p of tamperedParts) {
    if (p.kind === 'text') {
      p.text = p.text + ' (tampered)';
      break;
    }
  }
  const recomputedTampered = recomputeHash(tamperedParts);
  assert.notEqual(
    recomputedTampered,
    payload.outputs_hash,
    'a tampered artifact must NOT match the receipt outputs_hash — tamper is caught'
  );
});
