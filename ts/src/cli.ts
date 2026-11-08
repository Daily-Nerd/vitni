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
import { DUP_REJECT_COMMANDS, parseStrict } from './commands/strict-json.js';

async function readStdin(): Promise<Buffer> {
  // Robust across platforms: async-iterate the stream. Avoids the
  // readFileSync(0)/'/dev/stdin' EAGAIN-on-Linux-pipe failure seen in CI.
  // Raw bytes, never decoded here: toString('utf8') would silently replace an
  // invalid sequence with U+FFFD before the strict text gate could see it.
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks);
}

/**
 * The single table of CLI commands. Resolving the command here, before any
 * stdin byte is parsed, is what makes an unknown command answer
 * unsupported_command whatever the stdin looks like.
 */
const COMMANDS: Record<string, (input: unknown) => unknown> = {
  jcs: (i) => jcs(i as Parameters<typeof jcs>[0]),
  hashstring: (i) => hashstring(i as Parameters<typeof hashstring>[0]),
  digest: (i) => digest(i as Parameters<typeof digest>[0]),
  'receipt-id': (i) => receiptId(i as Parameters<typeof receiptId>[0]),
  'sse-outputs-hash': (i) => sseOutputsHash(i as Parameters<typeof sseOutputsHash>[0]),
  'cost-canon': (i) => costCanon(i as Parameters<typeof costCanon>[0]),
  verify: (i) => verify(i as Parameters<typeof verify>[0]),
  'verify-chain': (i) => verifyChain(i as Parameters<typeof verifyChain>[0]),
  'a2a-artifact-hash': (i) => a2aArtifactHash(i as Parameters<typeof a2aArtifactHash>[0]),
  sign: (i) => sign(i as Parameters<typeof sign>[0]),
  keygen: (i) => keygen(i),
};

/**
 * Run one command over its raw stdin bytes and return the JCS-canonical output
 * string (no trailing newline). Pure and side-effect-free so it is unit-testable
 * independently of stdin/argv wiring. Counterpart of Go's `respond`. Order:
 *
 *  1. the command resolves (unknown: unsupported_command, stdin never parsed);
 *  2. the stdin gate, ONCE for every command (parseStrict): strict UTF-8, no
 *     BOM, no lone-surrogate escape, exactly one JSON value, depth <= MAX_DEPTH,
 *     no non-finite number, duplicate keys per DUP_REJECT_COMMANDS, and the top
 *     level must be an object;
 *  3. the command runs on text that has already passed the gate.
 *
 * Any gate violation is invalid_input, a command error and never a verdict.
 * The catch-all below is a last resort that no stdin is meant to reach.
 */
export function dispatch(command: string, stdin: Uint8Array | string): string {
  if (!Object.prototype.hasOwnProperty.call(COMMANDS, command)) {
    return jcsString({ error: 'unsupported_command' });
  }
  const bytes = typeof stdin === 'string' ? Buffer.from(stdin, 'utf8') : stdin;
  const parsed = parseStrict(bytes, {
    rejectDuplicates: DUP_REJECT_COMMANDS.has(command),
    rejectNonFinite: true,
  });
  const input = parsed.ok ? parsed.value : undefined;
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return jcsString({ error: 'invalid_input' });
  }

  let result: unknown;
  try {
    result = COMMANDS[command](input);
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
  read: () => Promise<Uint8Array | string> = readStdin,
  write: (s: string) => void = (s) => { process.stdout.write(s); },
): Promise<void> {
  const command = argv[2];
  if (!command) {
    write(JSON.stringify({ error: 'missing_command' }) + '\n');
    return;
  }
  let raw: Uint8Array | string;
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
