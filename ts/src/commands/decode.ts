/**
 * Strict input decoders — deliberately reject what Node's lenient built-ins
 * accept, to stay byte-identical with the Go reference (which decodes via
 * encoding/base64 StdEncoding→RawStdEncoding and encoding/hex, both strict).
 *
 * DESIGN.md §4.1: the core admits exactly one encoding per byte source; a
 * lenient decoder that silently strips out-of-alphabet bytes would hash a
 * different octet string than a strict verifier and break interop.
 */

/**
 * Decode a standard-alphabet base64 string (`+/`, with or without padding),
 * matching Go's `base64.StdEncoding` then `base64.RawStdEncoding` fallback.
 * Returns null (caller maps to `invalid_input`) on any out-of-alphabet byte,
 * base64url char (`-_`), whitespace, or invalid length/padding.
 */
export function decodeStdBase64(s: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  if (s.includes('=')) {
    // StdEncoding: padded input must be a whole number of 4-char quanta.
    if (s.length % 4 !== 0) return null;
  } else if (s.length % 4 === 1) {
    // RawStdEncoding: a remainder of 1 is not a valid unpadded length.
    return null;
  }
  return Buffer.from(s, 'base64');
}

/**
 * Decode a hex string, matching Go's `encoding/hex.DecodeString`: rejects
 * odd length and any non-hex character. Node's `Buffer.from(s,'hex')` instead
 * silently truncates at the first bad nibble.
 */
export function decodeHex(s: string): Buffer | null {
  if (s.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(s)) return null;
  return Buffer.from(s, 'hex');
}
