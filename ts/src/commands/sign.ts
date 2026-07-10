/**
 * sign command — produce a deterministic EdDSA JWS signed receipt (conformance §10).
 *
 * Input:
 *   { "receipt": <Receipt WITHOUT receipt_id>, "kid": "<string>",
 *     "private_key_b64": "<base64 of a 32-byte Ed25519 RFC 8032 seed>" }
 * Output:
 *   { "signed_receipt": "<b64url(header).b64url(payload).b64url(sig)>" }
 *
 * The signing input and header/payload framing match the §7 verifier and the
 * MCP middleware signer exactly, so a produced receipt round-trips through verify
 * with no non_canonical_payload failure.
 *
 * KEY ENCODING (load-bearing): private_key_b64 is the 32-byte RFC 8032 seed — NOT
 * the 64-byte expanded key. The seed is the only runtime-portable form. node:crypto
 * has no direct "seed" import, so we wrap the seed into a PKCS8 DER by prefixing the
 * fixed 16-byte Ed25519 PKCS8 header, then importing it.
 */
import { createPrivateKey, sign as cryptoSign, KeyObject } from 'node:crypto';
import { jcsBytes, jcsString } from './jcs.js';
import { VERSION } from '../version.js';

export interface SignInput {
  receipt: Record<string, unknown>;
  kid: string;
  private_key_b64: string;
}

export interface SignOutput {
  signed_receipt: string;
}

/** The fixed 16-byte ASN.1/PKCS8 prefix for a raw Ed25519 private seed (RFC 8410). */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Closed set of top-level Receipt fields (§2); anything else is rejected at sign. */
const KNOWN_RECEIPT_KEYS = new Set([
  'v', 'binding', 'action_ref', 'performer_id', 'requester_id', 'method',
  'inputs_hash', 'outputs_hash', 'cost', 'status', 'reason',
  'parent_receipt_hash', 'parent_performer_id', 'log_policy', 'ts', 'nonce', 'ext',
]);

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

/**
 * Decode base64, accepting BOTH standard and raw (unpadded) base64 — matching the
 * `digest` command's tolerance. Returns null on invalid input.
 */
export function decodeFlexibleBase64(s: string): Buffer | null {
  // Node's 'base64' decoder is lenient and accepts both padded and unpadded input,
  // but it silently ignores trailing garbage. Re-encode and compare lengths to
  // reject genuinely malformed input while tolerating the padding difference.
  if (typeof s !== 'string') return null;
  try {
    const buf = Buffer.from(s, 'base64');
    // Round-trip guard: the decoded bytes must re-encode (no-pad) to the same
    // alphabet content as the input (ignoring '=' padding).
    const reencoded = buf.toString('base64').replace(/=+$/, '');
    const normalizedInput = s.replace(/=+$/, '');
    if (reencoded !== normalizedInput) return null;
    return buf;
  } catch {
    return null;
  }
}

/** Wrap a 32-byte Ed25519 seed into a node KeyObject. Returns null on failure. */
export function privateKeyFromSeed(seed: Buffer): KeyObject | null {
  if (seed.length !== 32) return null;
  try {
    const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch {
    return null;
  }
}

export function sign(input: SignInput): SignOutput | { error: string } {
  // --- validate input shape ---
  if (input === null || typeof input !== 'object') {
    return { error: 'invalid_input' };
  }
  const receipt = input.receipt;
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { error: 'invalid_input' };
  }

  // --- receipt_id must be absent (reuse the existing contract) ---
  if (Object.prototype.hasOwnProperty.call(receipt, 'receipt_id')) {
    return { error: 'receipt_id_must_be_absent' };
  }

  // --- reject unknown top-level keys (§2): the Receipt is a defined object;
  // forward-compatible extensions belong in `ext`. Signing over an unknown key
  // would let un-schema'd data into the signed bytes and receipt_id. ---
  for (const k of Object.keys(receipt)) {
    if (!KNOWN_RECEIPT_KEYS.has(k)) {
      return { error: 'invalid_input' };
    }
  }

  // --- cost magnitudes MUST be decimal strings (§4.1): reject a numeric (or
  // any non-string) magnitude, matching Go's typed-struct rejection. ---
  const cost = receipt.cost;
  if (cost !== null && typeof cost === 'object' && !Array.isArray(cost)) {
    for (const field of ['tokens', 'usd_micros', 'wall_ms'] as const) {
      const val = (cost as Record<string, unknown>)[field];
      if (val !== undefined && typeof val !== 'string') {
        return { error: 'invalid_input' };
      }
    }
  }

  // --- kid required ---
  const kid = input.kid;
  if (typeof kid !== 'string' || kid === '') {
    return { error: 'kid_required' };
  }

  // --- decode + validate the 32-byte seed ---
  if (typeof input.private_key_b64 !== 'string') {
    return { error: 'invalid_private_key' };
  }
  const seed = decodeFlexibleBase64(input.private_key_b64);
  if (seed === null || seed.length !== 32) {
    return { error: 'invalid_private_key' };
  }
  const privateKey = privateKeyFromSeed(seed);
  if (privateKey === null) {
    return { error: 'invalid_private_key' };
  }

  // --- stamp protocol version (mirrors vitni.Sign / the middleware) ---
  const payload = { ...receipt, v: VERSION };

  // --- frame: canonical header + JCS-canonical payload, EdDSA over the signing input ---
  const header = { alg: 'EdDSA', kid };
  const headerSeg = b64url(Buffer.from(jcsString(header), 'utf8'));
  const payloadSeg = b64url(jcsBytes(payload));
  const signingInput = Buffer.from(`${headerSeg}.${payloadSeg}`, 'ascii');
  const sig = cryptoSign(null, signingInput, privateKey);
  const signed_receipt = `${headerSeg}.${payloadSeg}.${b64url(sig)}`;

  return { signed_receipt };
}
