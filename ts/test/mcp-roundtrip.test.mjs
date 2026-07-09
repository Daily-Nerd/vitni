/**
 * End-to-end MCP binding test.
 *
 * Proves Vitni drops into a real MCP server (the official @modelcontextprotocol/sdk
 * over InMemoryTransport) and that a receipt round-trips through verification AND
 * actually binds the output the client received.
 *
 * Flow:
 *   server tool handler -> veritrail middleware attaches JWS at result._meta["dev.veritrail/receipt"]
 *   -> client calls tool over InMemoryTransport
 *   -> client extracts the JWS, verifies it with our §7 verify()
 *   -> client independently recomputes outputs_hash from the received result and asserts equality
 *   -> tamper test: flip a field of the result -> recomputed hash diverges -> tamper caught
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST = join(__dirname, '../dist');

const { verify } = await import(`${DIST}/commands/verify.js`);
const {
  generateTestSigner,
  computeOutputsHash,
  RECEIPT_META_KEY,
  registryFromSigner,
} = await import(`${DIST}/mcp/vitni-middleware.js`);
const { runRoundTrip } = await import(`${DIST}/mcp/server.js`);

test('mcp/roundtrip: receipt verifies and binds the received output', async () => {
  const signer = generateTestSigner();

  // Run the real MCP server+client round trip for tool `add(a,b)`.
  const { result, signer: usedSigner } = await runRoundTrip({
    signer,
    toolName: 'add',
    args: { a: 2, b: 3 },
  });

  // 1. The receipt JWS must sit at result._meta[RECEIPT_META_KEY]
  assert.ok(result._meta, 'result should carry _meta');
  const jws = result._meta[RECEIPT_META_KEY];
  assert.equal(typeof jws, 'string', 'receipt JWS must be a compact string');
  assert.equal(jws.split('.').length, 3, 'receipt must be a 3-part compact JWS');

  // 2. Verify with our §7 verify(), registry built from the published key.
  const keys = registryFromSigner(usedSigner);
  const v = verify({ signed_receipt: jws, keys, policy: { expected_binding: 'mcp', expected_method: 'mcp:add' } });
  assert.deepEqual(v, { valid: true, reason: 'ok' }, 'receipt must verify OK');

  // 3. Independently recompute outputs_hash from the result the CLIENT received.
  const payload = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'));
  const recomputed = computeOutputsHash(result);
  assert.equal(
    recomputed,
    payload.outputs_hash,
    'recomputed outputs_hash must match the receipt — proves the receipt binds the actual output'
  );
});

test('mcp/roundtrip: tampering the result is caught (receipt binds output)', async () => {
  const signer = generateTestSigner();
  const { result, signer: usedSigner } = await runRoundTrip({
    signer,
    toolName: 'add',
    args: { a: 2, b: 3 },
  });

  const jws = result._meta[RECEIPT_META_KEY];
  const payload = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'));

  // The signature still verifies (it's a real signature)...
  const keys = registryFromSigner(usedSigner);
  const v = verify({ signed_receipt: jws, keys, policy: { expected_binding: 'mcp', expected_method: 'mcp:add' } });
  assert.deepEqual(v, { valid: true, reason: 'ok' });

  // ...but tamper the result the client validates against: flip the structured output.
  const tampered = JSON.parse(JSON.stringify(result));
  tampered.structuredContent = { sum: 999 };
  if (tampered.content && tampered.content[0]) {
    tampered.content[0].text = '999';
  }

  const recomputedTampered = computeOutputsHash(tampered);
  assert.notEqual(
    recomputedTampered,
    payload.outputs_hash,
    'a tampered result must NOT match the receipt outputs_hash — tamper is caught'
  );
});
