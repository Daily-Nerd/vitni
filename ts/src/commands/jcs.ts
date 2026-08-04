/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Key rules:
 * - Object keys sorted by UTF-16 code units (RFC 8785 §3.2.3). Default JS
 *   string comparison IS code-unit order, so Array.prototype.sort() with no
 *   comparator is correct. (Note: this is NOT code-point order — they differ
 *   for non-BMP keys, e.g. "😀" sorts before "�" in code units.)
 * - Strings: verbatim, no normalization. JSON.stringify handles escaping.
 * - Numbers: ECMAScript Number→string (same as JSON.stringify), which is
 *   exactly what RFC 8785 §3.2.2 specifies.
 * - Arrays: order preserved.
 * - null, true, false: as-is.
 */

export function jcsBytes(value: unknown): Buffer {
  return Buffer.from(jcsString(value), 'utf8');
}

export function jcsString(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    // RFC 8785 §3.2.2: ECMAScript number serialization.
    // JSON.stringify for a bare number does exactly this.
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    // JSON.stringify handles escaping; no Unicode normalization.
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((v) => jcsString(v)).join(',');
    return `[${items}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    // Sort keys by UTF-16 code units (default JS sort) per RFC 8785 §3.2.3
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${jcsString(obj[k])}`);
    return `{${pairs.join(',')}}`;
  }
  // undefined, functions etc. — shouldn't appear in JSON input
  return 'null';
}

export interface JcsInput {
  value: unknown;
}

export interface JcsOutput {
  canonical_hex: string;
  byte_len: number;
}

export function jcs(input: JcsInput): JcsOutput {
  const bytes = jcsBytes(input.value);
  return {
    canonical_hex: bytes.toString('hex'),
    byte_len: bytes.length,
  };
}
