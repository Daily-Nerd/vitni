/**
 * Runnable Vitni + MCP integration demo.
 *
 *   node ts/dist/mcp/demo.js
 *
 * Prints the full flow: tool call -> receipt emitted -> verified OK -> tamper -> rejected.
 * Uses the real @modelcontextprotocol/sdk over InMemoryTransport.
 */
import { verify } from '../commands/verify.js';
import {
  generateTestSigner,
  registryFromSigner,
  computeOutputsHash,
  RECEIPT_META_KEY,
} from './vitni-middleware.js';
import { runRoundTrip } from './server.js';

function log(label: string, value?: unknown): void {
  if (value === undefined) {
    process.stdout.write(`${label}\n`);
  } else {
    process.stdout.write(`${label} ${typeof value === 'string' ? value : JSON.stringify(value)}\n`);
  }
}

async function main(): Promise<void> {
  log('=== Vitni × MCP integration demo ===\n');

  const signer = generateTestSigner();
  log('1. Tool call: add(a=2, b=3) over the official MCP SDK (InMemoryTransport)');

  const { result } = await runRoundTrip({ signer, toolName: 'add', args: { a: 2, b: 3 } });
  const sum = (result.structuredContent as { sum: number }).sum;
  log('   -> tool result:', { structuredContent: result.structuredContent });

  const jws = (result._meta as Record<string, string>)[RECEIPT_META_KEY];
  log(`2. Receipt emitted at result._meta["${RECEIPT_META_KEY}"]`);
  log('   -> JWS (compact):', jws.slice(0, 48) + '...');
  const payload = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'));
  log('   -> receipt.method:', payload.method);
  log('   -> receipt.outputs_hash:', payload.outputs_hash);

  log('3. Client verifies the receipt with §7 verify() against the published key');
  const keys = registryFromSigner(signer);
  const v = verify({
    signed_receipt: jws,
    keys,
    policy: { expected_binding: 'mcp', expected_method: 'mcp:add' },
  });
  log('   -> verify result:', v);
  if (!v.valid) throw new Error('demo failed: receipt did not verify');

  log('4. Client independently recomputes outputs_hash from the result it received');
  const recomputed = computeOutputsHash(result);
  const bound = recomputed === payload.outputs_hash;
  log('   -> recomputed outputs_hash:', recomputed);
  log('   -> matches receipt? ', bound);
  if (!bound) throw new Error('demo failed: receipt does not bind the actual output');
  log(`   ✓ receipt cryptographically binds the actual output (sum=${sum})\n`);

  log('5. TAMPER: an attacker rewrites the result to claim sum=999');
  const tampered = JSON.parse(JSON.stringify(result));
  tampered.structuredContent = { sum: 999 };
  tampered.content = [{ type: 'text', text: '999' }];
  const recomputedTampered = computeOutputsHash(tampered);
  log('   -> recomputed outputs_hash of tampered result:', recomputedTampered);
  const caught = recomputedTampered !== payload.outputs_hash;
  log('   -> differs from receipt? ', caught);
  if (!caught) throw new Error('demo failed: tamper not caught');
  log('   ✗ tamper REJECTED — the signed receipt does not match the forged output\n');

  log('=== demo complete: receipt round-tripped, output bound, tamper caught ===');
}

main().catch((err) => {
  process.stderr.write(`demo error: ${err}\n`);
  process.exit(1);
});
