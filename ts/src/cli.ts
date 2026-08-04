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
import { keygen } from './commands/keygen.js';
import { jcsString } from './commands/jcs.js';
import { rejectsForDuplicateKeys } from './commands/strict-json.js';

async function readStdin(): Promise<string> {
  // Robust across platforms: async-iterate the stream. Avoids the
  // readFileSync(0)/'/dev/stdin' EAGAIN-on-Linux-pipe failure seen in CI.
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Run one command over its raw stdin bytes and return the JCS-canonical output
 * string (no trailing newline). Pure and side-effect-free so it is unit-testable
 * independently of stdin/argv wiring.
 */
function hasNonFinite(v: unknown): boolean {
  if (typeof v === 'number') return !Number.isFinite(v);
  if (Array.isArray(v)) return v.some(hasNonFinite);
  if (v !== null && typeof v === 'object') return Object.values(v).some(hasNonFinite);
  return false;
}

export function dispatch(command: string, raw: string): string {
  let input: unknown;
  try {
    input = JSON.parse(raw);
  } catch {
    return jcsString({ error: 'invalid_input' });
  }

  // §4.1 (strict I-JSON): reject duplicate keys for the JCS-canonicalizing
  // commands, matching the Go reference (JSON.parse above silently kept last).
  if (rejectsForDuplicateKeys(command, raw)) {
    return jcsString({ error: 'invalid_input' });
  }

  // JSON.parse admits 1e400 as Infinity; serializing it would emit the bytes
  // "null" — silent corruption. Go rejects non-finite at parse; match it.
  if (hasNonFinite(input)) {
    return jcsString({ error: 'invalid_input' });
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
      case 'keygen':
        result = keygen(input);
        break;
      default:
        result = { error: 'unsupported_command' };
    }
  } catch {
    result = { error: 'internal_error' };
  }

  // Output must be JCS-canonical (sorted keys).
  return jcsString(result);
}

/**
 * Entry logic with injectable I/O so it is unit-testable independently of the
 * real process streams. Defaults wire the actual argv/stdin/stdout.
 */
export async function main(
  argv: readonly string[] = process.argv,
  read: () => Promise<string> = readStdin,
  write: (s: string) => void = (s) => { process.stdout.write(s); },
): Promise<void> {
  const command = argv[2];
  if (!command) {
    write(JSON.stringify({ error: 'missing_command' }) + '\n');
    return;
  }
  let raw: string;
  try {
    raw = await read();
  } catch {
    write(JSON.stringify({ error: 'stdin_read_error' }) + '\n');
    return;
  }
  write(dispatch(command, raw) + '\n');
}

/** Last-resort handler if main() itself rejects (should not happen in practice). */
export function writeFatal(): void {
  process.stdout.write(JSON.stringify({ error: 'internal_error' }) + '\n');
}

main().catch(writeFatal);
