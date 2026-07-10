/**
 * keygen command — generate an Ed25519 keypair, or (when seed_b64 is present)
 * deterministically derive the public key from a 32-byte RFC 8032 seed.
 *
 * Input:
 *   {}                       → fresh CSPRNG keypair
 *   { "seed_b64": "<b64>" }  → derive-only, no randomness consumed
 * Output:
 *   { "jwk": { "alg": "EdDSA", "crv": "Ed25519", "kty": "OKP",
 *              "status": "active", "x": "<b64url pubkey>" },
 *     "private_key_b64": "<std b64 of the 32-byte seed>" }
 *
 * The jwk pastes verbatim into the keys[performer_id][kid] slot of verify
 * input; status kept explicit so revocation semantics stay visible.
 *
 * ENCODING ASYMMETRY (deliberate): jwk.x is base64url-nopad because JWK
 * (RFC 7517/8037) mandates it; private_key_b64 is standard padded base64
 * because that is the form `sign` consumes. Do not normalize.
 *
 * A PRESENT-but-empty seed_b64 is invalid_seed, never treat-as-absent: a
 * buggy consumer passing "" must not silently receive a fresh random key.
 */
import { createPublicKey, randomBytes } from 'node:crypto';
import { decodeFlexibleBase64, privateKeyFromSeed } from './sign.js';

export interface KeygenJwk {
  alg: 'EdDSA';
  crv: 'Ed25519';
  kty: 'OKP';
  status: 'active';
  x: string;
}

export interface KeygenOutput {
  jwk: KeygenJwk;
  private_key_b64: string;
}

/**
 * The fixed 12-byte ASN.1/SPKI prefix node emits for a raw Ed25519 public key
 * (RFC 8410). Verified — never assumed — before slicing: a blind slice on an
 * unexpected DER layout would emit a wrong-but-plausible public key, the worst
 * failure mode for key tooling.
 */
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const SPKI_ED25519_LENGTH = 44;

export function keygen(input: unknown): KeygenOutput | { error: string } {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { error: 'invalid_input' };
  }
  const obj = input as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (k !== 'seed_b64') {
      return { error: 'invalid_input' };
    }
  }

  let seed: Buffer;
  if (!Object.prototype.hasOwnProperty.call(obj, 'seed_b64')) {
    seed = randomBytes(32);
  } else {
    if (typeof obj.seed_b64 !== 'string') {
      return { error: 'invalid_seed' };
    }
    const decoded = decodeFlexibleBase64(obj.seed_b64);
    if (decoded === null || decoded.length !== 32) {
      return { error: 'invalid_seed' };
    }
    seed = decoded;
  }

  const privateKey = privateKeyFromSeed(seed);
  if (privateKey === null) {
    return { error: 'invalid_seed' };
  }
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }) as Buffer;
  if (spki.length !== SPKI_ED25519_LENGTH || !spki.subarray(0, 12).equals(SPKI_ED25519_PREFIX)) {
    // Unexpected DER layout from the runtime — refuse rather than mis-slice.
    throw new Error('unexpected SPKI layout for Ed25519 public key');
  }
  const x = spki.subarray(12).toString('base64url');

  return {
    jwk: { alg: 'EdDSA', crv: 'Ed25519', kty: 'OKP', status: 'active', x },
    private_key_b64: seed.toString('base64'),
  };
}
