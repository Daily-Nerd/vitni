/**
 * Strict JSON text policy: the single owner of how external JSON text is
 * decoded in the TS impl (`parseStrict`), plus the duplicate-key scanner it uses.
 *
 * Counterpart of Go's ValidateJSONText. Base rules (always): no BOM, valid
 * UTF-8, exactly one JSON value, no lone-surrogate escape in any key or string,
 * nesting depth <= MAX_DEPTH. Per-site options: duplicate keys, non-finite
 * numbers.
 */
/** Pinned JSON nesting limit (DESIGN.md section 12 step 1). Top level is depth 1. */
export const MAX_DEPTH = 128;

export interface TextPolicy {
  /** Reject a duplicate object key anywhere in the text. */
  rejectDuplicates: boolean;
  /** Reject any number that overflows to +-Infinity. */
  rejectNonFinite: boolean;
}

export type StrictParse = { ok: true; value: unknown } | { ok: false };

/**
 * Decode `bytes` as one strict JSON value. Never throws: every violation is
 * `{ ok: false }` and the caller maps it to its own error code.
 *
 * Node 18 is the engine floor, so String.prototype.isWellFormed (Node 20) is not
 * used. JSON.parse turns a lone `\ud800` escape into a lone UTF-16 surrogate
 * with no error, and `/[\uD800-\uDFFF]/u` matches ONLY lone surrogates (a valid
 * pair is one code point under the `u` flag), so that is the detector.
 */
export function parseStrict(bytes: Uint8Array, p: TextPolicy): StrictParse {
  // Explicit BOM check: do not rely on TextDecoder BOM handling.
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { ok: false };
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { ok: false };
  }
  // Depth first: JSON.parse and the walks below recurse or iterate on the result,
  // so nothing deeper than MAX_DEPTH may reach them.
  if (!withinDepth(text)) return { ok: false };
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false };
  }
  if (hasLoneSurrogate(value)) return { ok: false };
  if (p.rejectDuplicates && hasDuplicateKeys(text)) return { ok: false };
  if (p.rejectNonFinite && hasNonFinite(value)) return { ok: false };
  return { ok: true, value };
}

/**
 * Decode JWS header or payload bytes: strict text that is exactly one JSON
 * object. Duplicate keys are last-wins and non-finite numbers are accepted here:
 * the header is never serialized, and a payload with either fails verify step 7
 * (its re-serialization cannot equal the transmitted bytes). Returns null on any
 * violation; the caller reports `malformed`.
 */
export function decodeJsonObject(bytes: Uint8Array): Record<string, unknown> | null {
  const r = parseStrict(bytes, { rejectDuplicates: false, rejectNonFinite: false });
  if (!r.ok) return null;
  const v = r.value;
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

/**
 * Whether a parsed value contains a number that overflowed to +-Infinity.
 * JSON.parse admits 1e400 as Infinity; serializing it would emit the bytes
 * "null", silent corruption that collides with a genuine null. Recursion is
 * bounded: callers run it only on values parseStrict already depth-limited.
 */
export function hasNonFinite(v: unknown): boolean {
  if (typeof v === 'number') return !Number.isFinite(v);
  if (Array.isArray(v)) return v.some(hasNonFinite);
  if (v !== null && typeof v === 'object') return Object.values(v).some(hasNonFinite);
  return false;
}

/**
 * One raw scan with string state; text is not yet known to be valid JSON. It
 * needs no syntactically valid input, so a site that skips text that is not JSON
 * at all can run it first: nesting over MAX_DEPTH is rejected, never "skipped".
 */
export function withinDepth(text: string): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++; // backslash: skip the escaped character
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x7b || c === 0x5b) {
      if (++depth > MAX_DEPTH) return false;
    } else if (c === 0x7d || c === 0x5d) {
      depth--;
    }
  }
  return true;
}

const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

/** Iterative walk over every key and string value (depth already bounded). */
function hasLoneSurrogate(root: unknown): boolean {
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === 'string') {
      if (LONE_SURROGATE.test(v)) return true;
    } else if (Array.isArray(v)) {
      for (const x of v) stack.push(x);
    } else if (v !== null && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        if (LONE_SURROGATE.test(k)) return true;
        stack.push(x);
      }
    }
  }
  return false;
}

/**
 * Duplicate-key detection over raw JSON text.
 *
 * JSON.parse silently keeps the last value for a duplicate object key, so a
 * parsed object cannot reveal that the input violated §4.1 (strict I-JSON:
 * "no duplicate keys"). The Go reference passes raw bytes to gowebpki/jcs,
 * which rejects duplicates at any nesting level; this scanner mirrors that so
 * the commands whose value flows into JCS (jcs, receipt-id, cost-canon) reject
 * the same inputs. It is a minimal structural scan — it assumes the text is
 * already valid JSON (JSON.parse ran first) and only looks for repeated keys.
 */

/**
 * The commands whose input value is canonicalized via JCS and therefore reject
 * duplicate keys, matching the Go reference (gowebpki/jcs errors on duplicates
 * at exactly these three; verify/digest/a2a/etc. keep-last, so they must NOT
 * reject here or the divergence flips the other way).
 */
export const DUP_REJECT_COMMANDS: ReadonlySet<string> = new Set(['jcs', 'receipt-id', 'cost-canon']);

export function hasDuplicateKeys(text: string): boolean {
  let i = 0;
  const n = text.length;

  // Skip a JSON string starting at text[i] === '"'; returns the index after it.
  function skipString(): void {
    i++; // opening quote
    while (i < n) {
      const c = text[i];
      if (c === '\\') {
        i += 2; // escape + escaped char (valid JSON already guaranteed)
        continue;
      }
      if (c === '"') {
        i++;
        return;
      }
      i++;
    }
  }

  // Read a JSON string value and return its decoded-enough form for comparison.
  // Keys rarely contain escapes, but handle the common ones so "a" and "a"
  // are treated per their literal source text (JCS compares by code point; for
  // duplicate detection, comparing the raw key text is sufficient and matches
  // how gowebpki/jcs keys off decoded strings — we decode escapes to be safe).
  function readString(): string {
    let out = '';
    i++; // opening quote
    while (i < n) {
      const c = text[i];
      if (c === '\\') {
        const e = text[i + 1];
        switch (e) {
          case 'n': out += '\n'; break;
          case 't': out += '\t'; break;
          case 'r': out += '\r'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case '/': out += '/'; break;
          case '\\': out += '\\'; break;
          case '"': out += '"'; break;
          case 'u': {
            const hex = text.slice(i + 2, i + 6);
            out += String.fromCharCode(parseInt(hex, 16));
            i += 6;
            continue;
          }
          default: out += e;
        }
        i += 2;
        continue;
      }
      if (c === '"') {
        i++;
        return out;
      }
      out += c;
      i++;
    }
    return out;
  }

  function skipWhitespace(): void {
    while (i < n && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  }

  // Recursively scan a value; returns true as soon as a duplicate key is found.
  function scanValue(): boolean {
    skipWhitespace();
    const c = text[i];
    if (c === '{') return scanObject();
    if (c === '[') return scanArray();
    if (c === '"') { skipString(); return false; }
    // number / true / false / null — skip until a structural boundary.
    while (i < n && !',}]'.includes(text[i])) i++;
    return false;
  }

  function scanArray(): boolean {
    i++; // '['
    while (i < n) {
      skipWhitespace();
      if (text[i] === ']') { i++; return false; }
      if (scanValue()) return true;
      skipWhitespace();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; return false; }
    }
    return false;
  }

  function scanObject(): boolean {
    i++; // '{'
    const keys = new Set<string>();
    while (i < n) {
      skipWhitespace();
      if (text[i] === '}') { i++; return false; }
      // key
      const key = readString();
      if (keys.has(key)) return true;
      keys.add(key);
      skipWhitespace();
      if (text[i] === ':') i++;
      if (scanValue()) return true;
      skipWhitespace();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return false; }
    }
    return false;
  }

  return scanValue();
}
