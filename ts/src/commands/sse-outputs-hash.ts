/**
 * sse-outputs-hash command — WHATWG SSE decode then hash (design §4.3).
 *
 * SSE parse rules (WHATWG html.spec.whatwg.org §9.2):
 *   1. Strip a single leading UTF-8 BOM (EF BB BF) if present.
 *   2. Normalize line terminators: \r\n, lone \r, lone \n → logical lines.
 *   3. data: field value = text after "data:" + one optional leading space.
 *   4. Multiple data: lines within one event join with "\n".
 *   5. Event dispatched on blank line; event with empty data NOT dispatched.
 *   6. Ignore comment (":"), event:, id:, retry: lines.
 *   7. Trailing event with no blank line NOT dispatched.
 *
 * committed = UTF8( join(message_data_strings, "\n") )
 *
 * For mode "sse-jsonrpc":
 *   each dispatched message data is a JSON-RPC message;
 *   committed unit = JCS(inner result), joined across messages with "\n".
 *   Messages without a "result" key are skipped.
 */
import { digestBytes } from './digest.js';
import { jcsBytes } from './jcs.js';
import { decodeStdBase64 } from './decode.js';

export interface SseInput {
  raw_b64: string;
  mode: 'sse' | 'sse-jsonrpc';
}

export interface SseOutput {
  decoded_hex: string;
  outputs_hash: string;
}

/**
 * Parse raw SSE bytes into an array of dispatched message data strings.
 * Follows WHATWG §9.2 exactly.
 */
function parseSse(raw: Buffer): string[] {
  // Step 1: Strip leading UTF-8 BOM if present
  let start = 0;
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    start = 3;
  }

  // Convert to string (UTF-8)
  const text = raw.subarray(start).toString('utf8');

  // Step 2: Split into logical lines, normalizing \r\n, lone \r, lone \n
  const lines = splitLines(text);

  // Step 3–7: Process lines per WHATWG event source processing model
  const dispatched: string[] = [];
  let dataBuf: string[] = [];

  for (const line of lines) {
    if (line === '') {
      // Blank line: dispatch event if data is non-empty
      if (dataBuf.length > 0) {
        // Join multiple data: lines with \n, no trailing \n
        dispatched.push(dataBuf.join('\n'));
      }
      // Reset event buffer (regardless of dispatch)
      dataBuf = [];
    } else if (line.startsWith(':')) {
      // Comment — ignore
    } else {
      // Parse field:value
      const colonIdx = line.indexOf(':');
      let field: string;
      let value: string;
      if (colonIdx === -1) {
        field = line;
        value = '';
      } else {
        field = line.slice(0, colonIdx);
        value = line.slice(colonIdx + 1);
        // Strip one optional leading space
        if (value.startsWith(' ')) {
          value = value.slice(1);
        }
      }

      if (field === 'data') {
        dataBuf.push(value);
      }
      // event:, id:, retry: — ignore (as per CONTRACT.md and §4.3)
    }
  }
  // Trailing event with no blank line is NOT dispatched (dataBuf is discarded)

  return dispatched;
}

/**
 * Split text into logical lines, normalizing \r\n, lone \r, lone \n.
 * Preserves empty strings for blank lines (event dispatch triggers).
 */
function splitLines(text: string): string[] {
  const lines: string[] = [];
  let i = 0;
  let lineStart = 0;

  while (i < text.length) {
    const ch = text[i];
    if (ch === '\r') {
      lines.push(text.slice(lineStart, i));
      if (i + 1 < text.length && text[i + 1] === '\n') {
        i += 2; // consume \r\n as one line terminator
      } else {
        i += 1;
      }
      lineStart = i;
    } else if (ch === '\n') {
      lines.push(text.slice(lineStart, i));
      i += 1;
      lineStart = i;
    } else {
      i += 1;
    }
  }
  // Remaining text after last terminator (no trailing newline case)
  // Per WHATWG: if there's no final blank line, the event is not dispatched,
  // but we still need to process any remaining non-blank content as lines.
  // We push it but it won't trigger a dispatch (no blank line follows).
  if (lineStart < text.length) {
    lines.push(text.slice(lineStart));
  }

  return lines;
}

export function sseOutputsHash(input: SseInput): SseOutput | { error: string } {
  if (input.mode !== 'sse' && input.mode !== 'sse-jsonrpc') {
    return { error: 'unsupported_mode' };
  }

  const raw = decodeStdBase64(input.raw_b64);
  if (raw === null) return { error: 'invalid_input' };
  const messages = parseSse(raw);

  let committed: Buffer;

  if (input.mode === 'sse') {
    // committed = UTF8(join(message_data_strings, "\n"))
    committed = Buffer.from(messages.join('\n'), 'utf8');
  } else {
    // sse-jsonrpc: for each message, parse as JSON, take .result, JCS it
    // Join JCS bytes with "\n"
    const parts: Buffer[] = [];
    for (const msg of messages) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(msg);
      } catch {
        // Not valid JSON — skip
        continue;
      }
      if (
        parsed !== null &&
        typeof parsed === 'object' &&
        !Array.isArray(parsed) &&
        Object.prototype.hasOwnProperty.call(parsed, 'result')
      ) {
        const result = (parsed as Record<string, unknown>)['result'];
        parts.push(jcsBytes(result));
      }
      // No result key → skip
    }
    // Join with \n (as bytes)
    const newline = Buffer.from('\n', 'utf8');
    const totalLen = parts.reduce((acc, p, i) => acc + p.length + (i > 0 ? 1 : 0), 0);
    committed = Buffer.alloc(totalLen);
    let offset = 0;
    for (let i = 0; i < parts.length; i++) {
      if (i > 0) {
        newline.copy(committed, offset);
        offset += 1;
      }
      parts[i].copy(committed, offset);
      offset += parts[i].length;
    }
  }

  const outputs_hash = digestBytes(committed);

  return {
    decoded_hex: committed.toString('hex'),
    outputs_hash,
  };
}
