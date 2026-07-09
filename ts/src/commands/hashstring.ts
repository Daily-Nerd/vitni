/**
 * hashstring command — multihash + multibase encoding.
 *
 * Format: "u" + base64url-nopad( 0x12 || 0x20 || raw_digest_bytes )
 *   - 0x12 = multihash code for sha2-256
 *   - 0x20 = 32 (decimal) = digest length in bytes
 *   - multibase prefix "u" = base64url (no padding)
 *
 * Only supports algo "sha2-256" (code 0x12, length 0x20 = 32).
 */
import { decodeHex } from './decode.js';

export interface HashstringInput {
  algo: string;
  digest_hex: string;
}

export interface HashstringOutput {
  hashstr: string;
}

export function encodeHashstring(digestBytes: Buffer): string {
  // multihash: varint(0x12) || varint(0x20) || digest
  // Both 0x12 and 0x20 are single-byte varints (< 0x80)
  const mh = Buffer.alloc(2 + digestBytes.length);
  mh[0] = 0x12; // sha2-256 code
  mh[1] = 0x20; // 32 bytes length
  digestBytes.copy(mh, 2);
  // base64url no-padding
  const b64url = mh.toString('base64url');
  return `u${b64url}`;
}

export function hashstring(input: HashstringInput): HashstringOutput | { error: string } {
  if (input.algo !== 'sha2-256') {
    return { error: 'unsupported_algo' };
  }
  const digestBytes = decodeHex(input.digest_hex);
  if (digestBytes === null) return { error: 'invalid_input' };
  return { hashstr: encodeHashstring(digestBytes) };
}
