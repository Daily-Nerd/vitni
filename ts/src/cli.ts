#!/usr/bin/env node
/**
 * Vitni conformance verifier CLI — TypeScript implementation.
 *
 * Usage: node dist/cli.js <command> < input.json
 *
 * Reads input JSON from stdin, command from argv[2].
 * Emits exactly one JCS-canonical JSON line to stdout, exit 0.
 * On error, emits {"error":"<code>"} to stdout, exit 0.
 * No logs/banners to stdout (use stderr).
 */
import { jcs } from './commands/jcs.js';
import { hashstring } from './commands/hashstring.js';
import { digest } from './commands/digest.js';
import { receiptId } from './commands/receipt-id.js';
import { sseOutputsHash } from './commands/sse-outputs-hash.js';
import { costCanon } from './commands/cost-canon.js';
import { verify } from './commands/verify.js';
import { verifyChain } from './commands/verify-chain.js';
import { a2aArtifactHash } from './commands/a2a-artifact-hash.js';
import { sign } from './commands/sign.js';
import { jcsString } from './commands/jcs.js';

async function readStdin(): Promise<string> {
  // Robust across platforms: async-iterate the stream. Avoids the
  // readFileSync(0)/'/dev/stdin' EAGAIN-on-Linux-pipe failure seen in CI.
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main() {
  const command = process.argv[2];
  if (!command) {
    process.stdout.write(JSON.stringify({ error: 'missing_command' }) + '\n');
    return;
  }

  let raw: string;
  try {
    raw = await readStdin();
  } catch {
    process.stdout.write(JSON.stringify({ error: 'stdin_read_error' }) + '\n');
    return;
  }

  let input: unknown;
  try {
    input = JSON.parse(raw);
  } catch {
    process.stdout.write(JSON.stringify({ error: 'invalid_json' }) + '\n');
    return;
  }

  let result: unknown;
  try {
    switch (command) {
      case 'jcs':
        result = jcs(input as Parameters<typeof jcs>[0]);
        break;
      case 'hashstring':
        result = hashstring(input as Parameters<typeof hashstring>[0]);
        break;
      case 'digest':
        result = digest(input as Parameters<typeof digest>[0]);
        break;
      case 'receipt-id':
        result = receiptId(input as Parameters<typeof receiptId>[0]);
        break;
      case 'sse-outputs-hash':
        result = sseOutputsHash(input as Parameters<typeof sseOutputsHash>[0]);
        break;
      case 'cost-canon':
        result = costCanon(input as Parameters<typeof costCanon>[0]);
        break;
      case 'verify':
        result = verify(input as Parameters<typeof verify>[0]);
        break;
      case 'verify-chain':
        result = verifyChain(input as Parameters<typeof verifyChain>[0]);
        break;
      case 'a2a-artifact-hash':
        result = a2aArtifactHash(input as Parameters<typeof a2aArtifactHash>[0]);
        break;
      case 'sign':
        result = sign(input as Parameters<typeof sign>[0]);
        break;
      default:
        result = { error: 'unknown_command' };
    }
  } catch (err) {
    process.stderr.write(`Error: ${err}\n`);
    result = { error: 'internal_error' };
  }

  // Output must be JCS-canonical (sorted keys) — use jcsString for output
  process.stdout.write(jcsString(result) + '\n');
}

main().catch(() => {
  process.stdout.write(JSON.stringify({ error: 'internal_error' }) + '\n');
});
