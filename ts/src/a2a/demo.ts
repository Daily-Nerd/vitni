/**
 * Runnable Vitni + A2A integration demo.
 *
 *   node ts/dist/a2a/demo.js
 *
 * Prints the full flow: task artifact produced -> receipt emitted -> verified OK ->
 * §9 outputs_hash recomputed & matched -> tamper -> rejected.
 * Uses the real @a2a-js/sdk server stack (DefaultRequestHandler + InMemoryTaskStore).
 */
import { verify } from '../commands/verify.js';
import { a2aArtifactHash } from '../commands/a2a-artifact-hash.js';
import { generateTestSigner, registryFromSigner } from '../mcp/vitni-middleware.js';
import { RECEIPT_META_KEY } from './vitni-a2a-middleware.js';
import { runA2ARoundTrip } from './server.js';

function log(label: string, value?: unknown): void {
  if (value === undefined) process.stdout.write(`${label}\n`);
  else process.stdout.write(`${label} ${typeof value === 'string' ? value : JSON.stringify(value)}\n`);
}

function hashOfParts(parts: unknown[]): string {
  const res = a2aArtifactHash({ artifact: { parts } } as Parameters<typeof a2aArtifactHash>[0]);
  if ('error' in res) throw new Error(res.error);
  return res.outputs_hash;
}

async function main(): Promise<void> {
  log('=== Vitni × A2A integration demo ===\n');

  const signer = generateTestSigner();
  log('1. A2A task: skill "summarize" over the official @a2a-js/sdk server stack');

  const { artifact } = await runA2ARoundTrip({ signer, skill: 'summarize', text: 'hello world' });
  log('   -> artifact.parts:', artifact.parts);

  const jws = (artifact.metadata as Record<string, string>)[RECEIPT_META_KEY];
  log(`2. Receipt emitted at artifact.metadata["${RECEIPT_META_KEY}"]`);
  log('   -> JWS (compact):', jws.slice(0, 48) + '...');
  const payload = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'));
  log('   -> receipt.binding:', payload.binding);
  log('   -> receipt.method:', payload.method);
  log('   -> receipt.outputs_hash:', payload.outputs_hash);

  log('3. Consumer verifies the receipt with §7 verify() against the published key');
  const keys = registryFromSigner(signer);
  const v = verify({
    signed_receipt: jws,
    keys,
    policy: { expected_binding: 'a2a', expected_method: 'a2a:summarize' },
  });
  log('   -> verify result:', v);
  if (!v.valid) throw new Error('demo failed: receipt did not verify');

  log('4. Consumer independently recomputes the §9 outputs_hash over the artifact parts');
  const recomputed = hashOfParts(artifact.parts as unknown[]);
  const bound = recomputed === payload.outputs_hash;
  log('   -> recomputed §9 outputs_hash:', recomputed);
  log('   -> matches receipt? ', bound);
  if (!bound) throw new Error('demo failed: receipt does not bind the artifact');
  log('   ✓ receipt cryptographically binds the actual artifact\n');

  log('5. TAMPER: an attacker rewrites the artifact text part');
  const tamperedParts = JSON.parse(JSON.stringify(artifact.parts));
  for (const p of tamperedParts) {
    if (p.kind === 'text') {
      p.text = p.text + ' (tampered)';
      break;
    }
  }
  const recomputedTampered = hashOfParts(tamperedParts);
  log('   -> recomputed §9 outputs_hash of tampered artifact:', recomputedTampered);
  const caught = recomputedTampered !== payload.outputs_hash;
  log('   -> differs from receipt? ', caught);
  if (!caught) throw new Error('demo failed: tamper not caught');
  log('   ✗ tamper REJECTED — the signed receipt does not match the forged artifact\n');

  log('=== demo complete: A2A artifact receipt round-tripped, output bound, tamper caught ===');
}

main().catch((err) => {
  process.stderr.write(`demo error: ${err}\n`);
  process.exit(1);
});
