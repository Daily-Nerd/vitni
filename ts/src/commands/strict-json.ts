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

/**
 * The single UTF-8 decoder for external bytes: fatal, so an invalid sequence
 * (stray byte, truncated, overlong, encoded surrogate) is `null` and U+FFFD is
 * never produced. A BOM is kept as a character, not stripped; callers that
 * reject or strip it do so on the bytes first. Buffer#toString('utf8') must
 * not decode external bytes anywhere: it replaces silently.
 */
export function decodeUtf8Strict(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

export type StrictParse = { ok: true; value: unknown } | { ok: false };

/**
 * Decode `bytes` as one strict JSON value. Never throws: every violation is
 * `{ ok: false }` and the caller maps it to its own error code.
 *
 * Node 18 is the engine floor, so String.prototype.isWellFormed (Node 20) is not
 * used. JSON.parse turns a lone `\ud800` escape into a lone UTF-16 surrogate
 * with no error, so the escapes are judged in the raw text by `scanText`
 * (strict UTF-8 decoding has already rejected every raw surrogate code unit).
 */
export function parseStrict(bytes: Uint8Array, p: TextPolicy): StrictParse {
  // Explicit BOM check: do not rely on TextDecoder BOM handling.
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { ok: false };
  }
  const text = decodeUtf8Strict(bytes);
  if (text === null) return { ok: false };
  // One raw pass before JSON.parse: depth (nothing deeper than MAX_DEPTH may
  // reach the parser or later recursion), lone-surrogate escapes, and, per
  // policy, non-finite numbers. No walk over the parsed value is needed.
  if (!scanText(text, { surrogates: true, nonFinite: p.rejectNonFinite })) return { ok: false };
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false };
  }
  if (p.rejectDuplicates && hasDuplicateKeys(text)) return { ok: false };
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

export interface ScanOptions {
  /** Reject a lone surrogate `\uXXXX` escape in any key or string value. */
  surrogates: boolean;
  /** Reject a number token whose value is not finite (1e400, -1e400). */
  nonFinite: boolean;
}

const NO_CHECKS: ScanOptions = { surrogates: false, nonFinite: false };

const isDigit = (c: number): boolean => c >= 0x30 && c <= 0x39;
// Characters of a JSON number token: digits, '.', 'e', 'E', '+', '-'.
const isNumberChar = (c: number): boolean =>
  isDigit(c) || c === 0x2e || c === 0x65 || c === 0x45 || c === 0x2b || c === 0x2d;

/** Value of a hex digit, or -1. Case-insensitive. */
function hexValue(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return -1;
}

/**
 * The one raw scan of the gate, with string state. It returns true when the
 * text passes every enabled check. The text is NOT yet known to be valid JSON,
 * so every answer it gives on invalid text must be harmless: a `false` there is
 * a reject the caller (JSON.parse) would have made anyway, a `true` is followed
 * by JSON.parse. The checks:
 *
 *  - depth (always): nesting over MAX_DEPTH is rejected, never "skipped".
 *    Needs no valid input, so a site that skips text that is not JSON at all
 *    can run it first (sse-jsonrpc). With both options off it judges nothing
 *    else, whatever the text.
 *  - surrogates: the strict UTF-8 decode already rejected raw surrogate code
 *    units, so only escapes matter. In a string (key or value) a high escape
 *    (D800-DBFF) must be followed immediately by a low escape (DC00-DFFF), and a
 *    low escape must follow a high one. `\\ud800` is an escaped backslash and a
 *    `u`, not an escape. Hex is case-insensitive. A `\u` not followed by four
 *    hex digits is invalid JSON and is rejected here.
 *  - nonFinite: a number token starts at '-' or a digit outside a string and
 *    runs over the characters of a JSON number; it is rejected when
 *    `Number(token)` is not finite. true/false/null start with a letter, so
 *    their 'e' never starts a token.
 */
export function scanText(text: string, opts: ScanOptions): boolean {
  const { surrogates, nonFinite } = opts;
  const n = text.length;
  let depth = 0;
  let inString = false;
  let high = false; // inside a string, the previous item was a high-surrogate escape
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) {
        // backslash: the escaped character is never a quote or an escape start
        if (surrogates && text.charCodeAt(i + 1) === 0x75) {
          const h0 = hexValue(text.charCodeAt(i + 2));
          const h1 = hexValue(text.charCodeAt(i + 3));
          const h2 = hexValue(text.charCodeAt(i + 4));
          const h3 = hexValue(text.charCodeAt(i + 5));
          if ((h0 | h1 | h2 | h3) < 0) return false; // invalid JSON
          const unit = (h0 << 12) | (h1 << 8) | (h2 << 4) | h3;
          if (unit >= 0xd800 && unit <= 0xdbff) {
            if (high) return false; // high followed by high
            high = true;
          } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            if (!high) return false; // low without a high before it
            high = false;
          } else if (high) {
            return false; // high followed by a non-low escape
          }
          i += 5;
        } else {
          if (high) return false; // high followed by another escape
          i++;
        }
      } else if (c === 0x22) {
        if (high) return false; // high at the end of the string
        inString = false;
      } else if (high) {
        return false; // high followed by an ordinary character
      }
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x7b || c === 0x5b) {
      if (++depth > MAX_DEPTH) return false;
    } else if (c === 0x7d || c === 0x5d) {
      depth--;
    } else if (nonFinite && (c === 0x2d || isDigit(c))) {
      let j = i + 1;
      while (j < n && isNumberChar(text.charCodeAt(j))) j++;
      if (!Number.isFinite(Number(text.slice(i, j)))) return false;
      i = j - 1;
    }
  }
  return true;
}

/** Depth only: see `scanText`. */
export function withinDepth(text: string): boolean {
  return scanText(text, NO_CHECKS);
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
