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
const DUP_REJECT_COMMANDS = new Set(['jcs', 'receipt-id', 'cost-canon']);

/**
 * Whether the raw stdin for `command` must be rejected for a duplicate key.
 * True only for the JCS-canonicalizing commands with a duplicate present.
 */
export function rejectsForDuplicateKeys(command: string, raw: string): boolean {
  return DUP_REJECT_COMMANDS.has(command) && hasDuplicateKeys(raw);
}

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
