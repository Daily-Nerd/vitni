/**
 * verify command — JWS signature verification + JOSE hardening (design §3, §12).
 *
 * Verification algorithm (first failing check wins, in THIS exact order):
 *  1. malformed            — not 3 b64url segments / header|payload not valid JSON / payload not valid UTF-8.
 *  2. header_key_material  — header contains ANY of jwk/jku/x5u/x5c/x5t/x5t#S256.
 *  3. unknown_key          — performer_id (from payload) / kid (from header) absent or not in keys.
 *  4. revoked_key          — resolved key status == "revoked".
 *  5. alg_not_allowed      : header alg is none/absent, OR header alg != resolved key alg,
 *                            OR the key's alg/kty/crv is not a row of the ALGS table.
 *  6. bad_signature        — signature fails over b64url(header).b64url(payload).
 *  7. non_canonical_payload— decode(payload) != JCS(parse(payload)) byte-for-byte.
 *  8. context_mismatch     — policy.expected_binding/expected_method set and != payload's.
 *  9. ok.
 *
 * Output: { valid, reason } as JCS-canonical JSON (CLI applies JCS).
 */
import { createPublicKey, verify as cryptoVerify, KeyObject } from 'node:crypto';
import { jcsBytes } from './jcs.js';
import { decodeB64UrlStrict } from './decode.js';
import { decodeJsonObject } from './strict-json.js';

export interface VerifyInput {
  signed_receipt: string;
  keys: Record<string, Record<string, RegistryJwk>>;
  policy?: {
    expected_binding?: string | null;
    expected_method?: string | null;
  };
}

export interface RegistryJwk {
  kty: string;
  crv: string;
  x: string;
  y?: string;
  alg: string;
  status?: string;
}

export interface VerifyOutput {
  valid: boolean;
  reason: string;
}

/**
 * The algorithm table: the SINGLE owner of {alg -> kty, crv}. Step 5 (key-type
 * binding), key construction in step 6 and the declared alg set all derive
 * from it, so "algs we verify" and "algs we declare" cannot drift.
 */
export const ALGS = {
  EdDSA: { kty: 'OKP', crv: 'Ed25519' },
  ES256: { kty: 'EC', crv: 'P-256' },
} as const;

type AlgName = keyof typeof ALGS;

function isKnownAlg(alg: unknown): alg is AlgName {
  return typeof alg === 'string' && Object.prototype.hasOwnProperty.call(ALGS, alg);
}

const FORBIDDEN_HEADER_KEYS = ['jwk', 'jku', 'x5u', 'x5c', 'x5t', 'x5t#S256'];

function fail(reason: string): VerifyOutput {
  return { valid: false, reason };
}

/**
 * Build a node KeyObject from a registry JWK for the given alg. Key coordinates
 * go through the one strict base64url decoder and must be exactly 32 bytes; the
 * JWK handed to Node is rebuilt from the RE-ENCODED canonical strings, so Node's
 * lenient JWK import (padding, std alphabet, trailing bits, extra bytes) never
 * sees raw registry input. Any key-material problem returns null, which the
 * caller reports as `bad_signature` (a JWS segment failing the same decoder is
 * `malformed`: same decoder, different code at the call site).
 */
function buildPublicKey(jwk: RegistryJwk, alg: string): KeyObject | null {
  const x = decodeB64UrlStrict(jwk.x);
  if (x === null || x.length !== 32) return null;
  let jwkFields: Record<string, string>;
  if (alg === 'EdDSA') {
    jwkFields = { ...ALGS.EdDSA, x: x.toString('base64url') };
  } else if (alg === 'ES256') {
    const y = decodeB64UrlStrict(jwk.y as string);
    if (y === null || y.length !== 32) return null;
    jwkFields = {
      ...ALGS.ES256,
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    };
  } else {
    return null;
  }
  try {
    return createPublicKey({ key: jwkFields, format: 'jwk' });
  } catch {
    return null;
  }
}

function verifySignature(
  alg: string,
  signingInput: Buffer,
  keyObj: KeyObject,
  sig: Buffer
): boolean {
  try {
    if (alg === 'EdDSA') {
      // Ed25519: algorithm is null (the curve determines the hash).
      return cryptoVerify(null, signingInput, keyObj, sig);
    }
    if (alg === 'ES256') {
      // JWS ES256 signature is raw R||S (64 bytes) — ieee-p1363 encoding.
      return cryptoVerify(
        'sha256',
        signingInput,
        { key: keyObj, dsaEncoding: 'ieee-p1363' },
        sig
      );
    }
    return false;
  } catch {
    return false;
  }
}

export function verify(input: VerifyInput): VerifyOutput {
  const jws = input.signed_receipt;

  // --- Step 1: malformed (structure) ---
  if (typeof jws !== 'string') return fail('malformed');
  const parts = jws.split('.');
  if (parts.length !== 3) return fail('malformed');
  const [headerSeg, payloadSeg, sigSeg] = parts;

  const headerBuf = decodeB64UrlStrict(headerSeg);
  const payloadBuf = decodeB64UrlStrict(payloadSeg);
  const sigBuf = decodeB64UrlStrict(sigSeg);
  if (headerBuf === null || payloadBuf === null || sigBuf === null) {
    return fail('malformed');
  }

  // header: strict text that is exactly one JSON object.
  const header = decodeJsonObject(headerBuf);
  if (header === null) return fail('malformed');
  // RFC 7797: b64 absent or true is fine; false or any non-boolean is malformed.
  if (Object.prototype.hasOwnProperty.call(header, 'b64') && header['b64'] !== true) {
    return fail('malformed');
  }

  // payload: same strict text, exactly one object (§7 step 1, fail fast).
  const payload = decodeJsonObject(payloadBuf);
  if (payload === null) return fail('malformed');

  // --- Step 2: header_key_material ---
  for (const k of FORBIDDEN_HEADER_KEYS) {
    if (Object.prototype.hasOwnProperty.call(header, k)) {
      return fail('header_key_material');
    }
  }

  // --- Step 3: resolve key (unknown_key) ---
  const performerId = payload['performer_id'];
  const kid = header['kid'];
  if (typeof performerId !== 'string' || typeof kid !== 'string') {
    return fail('unknown_key');
  }
  const perfKeys = input.keys?.[performerId];
  if (!perfKeys) return fail('unknown_key');
  const jwk = perfKeys[kid];
  if (!jwk) return fail('unknown_key');

  // --- Step 4: revoked_key ---
  if (jwk.status === 'revoked') {
    return fail('revoked_key');
  }

  // --- Step 5: alg_not_allowed ---
  const headerAlg = header['alg'];
  if (
    typeof headerAlg !== 'string' ||
    headerAlg === 'none' ||
    headerAlg === '' ||
    headerAlg !== jwk.alg
  ) {
    return fail('alg_not_allowed');
  }
  // The registry key must be the key type its alg requires. An alg outside the
  // table, and a missing or null kty/crv, fail here, before any key material is
  // decoded. Runs after step 4 (a revoked key stays revoked_key) and after the
  // header/registry alg equality above.
  if (
    !isKnownAlg(jwk.alg) ||
    jwk.kty !== ALGS[jwk.alg].kty ||
    jwk.crv !== ALGS[jwk.alg].crv
  ) {
    return fail('alg_not_allowed');
  }

  // --- Step 6: bad_signature ---
  const keyObj = buildPublicKey(jwk, headerAlg);
  if (keyObj === null) return fail('bad_signature');
  // signingInput = ASCII b64u(header).b64u(payload)
  const signingInput = Buffer.from(`${headerSeg}.${payloadSeg}`, 'ascii');
  if (!verifySignature(headerAlg, signingInput, keyObj, sigBuf)) {
    return fail('bad_signature');
  }

  // --- Step 7: non_canonical_payload ---
  // payload bytes (as transmitted) must equal JCS(parse(payload)) byte-for-byte.
  const canonical = jcsBytes(payload);
  if (!canonical.equals(payloadBuf)) {
    return fail('non_canonical_payload');
  }

  // --- Step 8: context_mismatch ---
  const expectedBinding = input.policy?.expected_binding;
  const expectedMethod = input.policy?.expected_method;
  if (
    expectedBinding !== undefined &&
    expectedBinding !== null &&
    payload['binding'] !== expectedBinding
  ) {
    return fail('context_mismatch');
  }
  if (
    expectedMethod !== undefined &&
    expectedMethod !== null &&
    payload['method'] !== expectedMethod
  ) {
    return fail('context_mismatch');
  }

  // --- Step 9: ok ---
  return { valid: true, reason: 'ok' };
}
