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

/**
 * The registry lookup: the SINGLE owner of "answers only for keys the registry
 * actually contains". Own properties only, at both levels, so a performer_id or
 * kid named like something every object inherits (__proto__, constructor,
 * toString) is absent, as in Go. A key that really is in the registry (JSON.parse
 * defines `__proto__` as an own property) is found.
 */
function lookupKey(
  keys: VerifyInput['keys'] | null | undefined,
  performerId: string,
  kid: string
): RegistryJwk | null {
  const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
  if (keys === null || keys === undefined || !has(keys, performerId)) return null;
  const perfKeys = keys[performerId];
  if (perfKeys === null || perfKeys === undefined || !has(perfKeys, kid)) return null;
  return perfKeys[kid] ?? null;
}

const FORBIDDEN_HEADER_KEYS = ['jwk', 'jku', 'x5u', 'x5c', 'x5t', 'x5t#S256'];

function rejected(reason: string): { result: VerifyOutput; decoded: null } {
  return { result: { valid: false, reason }, decoded: null };
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
function buildPublicKey(jwk: RegistryJwk, alg: AlgName): KeyObject | null {
  const x = decodeB64UrlStrict(jwk.x);
  if (x === null || x.length !== 32) return null;
  let jwkFields: Record<string, string>;
  if (alg === 'EdDSA') {
    jwkFields = { ...ALGS.EdDSA, x: x.toString('base64url') };
  } else {
    const y = decodeB64UrlStrict(jwk.y as string);
    if (y === null || y.length !== 32) return null;
    jwkFields = {
      ...ALGS.ES256,
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    };
  }
  try {
    return createPublicKey({ key: jwkFields, format: 'jwk' });
  } catch {
    return null;
  }
}

/**
 * Verify the signature with a key built for the same alg. Never throws: the
 * kty/crv/alg binding (step 5) and buildPublicKey (which returns null for any
 * key Node cannot import) leave only inputs on which crypto.verify returns a
 * boolean, whatever the signature length or content. A genuine bug must reach
 * the CLI as internal_error, not be swallowed into bad_signature.
 */
function verifySignature(
  alg: AlgName,
  signingInput: Buffer,
  keyObj: KeyObject,
  sig: Buffer
): boolean {
  if (alg === 'EdDSA') {
    // Ed25519: algorithm is null (the curve determines the hash).
    return cryptoVerify(null, signingInput, keyObj, sig);
  }
  // ES256: JWS signature is raw R||S (64 bytes), ieee-p1363 encoding.
  return cryptoVerify('sha256', signingInput, { key: keyObj, dsaEncoding: 'ieee-p1363' }, sig);
}

export function verify(input: VerifyInput): VerifyOutput {
  return verifyDecoded(input).result;
}

/** The payload verify accepted: transmitted bytes (JCS-equal after step 7) and the parsed object. */
export interface DecodedReceipt {
  payloadBytes: Buffer;
  payload: Record<string, unknown>;
}

/**
 * verify's body. On success it also hands back the payload it already decoded,
 * so verify-chain never decodes the same bytes twice.
 */
export function verifyDecoded(input: VerifyInput): {
  result: VerifyOutput;
  decoded: DecodedReceipt | null;
} {
  const jws = input.signed_receipt;

  // --- Step 1: malformed (structure) ---
  if (typeof jws !== 'string') return rejected('malformed');
  const parts = jws.split('.');
  if (parts.length !== 3) return rejected('malformed');
  const [headerSeg, payloadSeg, sigSeg] = parts;

  const headerBuf = decodeB64UrlStrict(headerSeg);
  const payloadBuf = decodeB64UrlStrict(payloadSeg);
  const sigBuf = decodeB64UrlStrict(sigSeg);
  if (headerBuf === null || payloadBuf === null || sigBuf === null) {
    return rejected('malformed');
  }

  // header: strict text that is exactly one JSON object.
  const header = decodeJsonObject(headerBuf);
  if (header === null) return rejected('malformed');
  // RFC 7797: b64 absent or true is fine; false or any non-boolean is malformed.
  if (Object.prototype.hasOwnProperty.call(header, 'b64') && header['b64'] !== true) {
    return rejected('malformed');
  }

  // payload: same strict text, exactly one object (§7 step 1, fail fast).
  const payload = decodeJsonObject(payloadBuf);
  if (payload === null) return rejected('malformed');

  // --- Step 2: header_key_material ---
  for (const k of FORBIDDEN_HEADER_KEYS) {
    if (Object.prototype.hasOwnProperty.call(header, k)) {
      return rejected('header_key_material');
    }
  }

  // --- Step 3: resolve key (unknown_key) ---
  const performerId = payload['performer_id'];
  const kid = header['kid'];
  if (typeof performerId !== 'string' || typeof kid !== 'string') {
    return rejected('unknown_key');
  }
  const jwk = lookupKey(input.keys, performerId, kid);
  if (jwk === null) return rejected('unknown_key');

  // --- Step 4: revoked_key ---
  if (jwk.status === 'revoked') {
    return rejected('revoked_key');
  }

  // --- Step 5: alg_not_allowed ---
  const headerAlg = header['alg'];
  if (
    typeof headerAlg !== 'string' ||
    headerAlg === 'none' ||
    headerAlg === '' ||
    headerAlg !== jwk.alg
  ) {
    return rejected('alg_not_allowed');
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
    return rejected('alg_not_allowed');
  }

  // --- Step 6: bad_signature ---
  const keyObj = buildPublicKey(jwk, jwk.alg);
  if (keyObj === null) return rejected('bad_signature');
  // signingInput = ASCII b64u(header).b64u(payload)
  const signingInput = Buffer.from(`${headerSeg}.${payloadSeg}`, 'ascii');
  if (!verifySignature(jwk.alg, signingInput, keyObj, sigBuf)) {
    return rejected('bad_signature');
  }

  // --- Step 7: non_canonical_payload ---
  // payload bytes (as transmitted) must equal JCS(parse(payload)) byte-for-byte.
  const canonical = jcsBytes(payload);
  if (!canonical.equals(payloadBuf)) {
    return rejected('non_canonical_payload');
  }

  // --- Step 8: context_mismatch ---
  const expectedBinding = input.policy?.expected_binding;
  const expectedMethod = input.policy?.expected_method;
  if (
    expectedBinding !== undefined &&
    expectedBinding !== null &&
    payload['binding'] !== expectedBinding
  ) {
    return rejected('context_mismatch');
  }
  if (
    expectedMethod !== undefined &&
    expectedMethod !== null &&
    payload['method'] !== expectedMethod
  ) {
    return rejected('context_mismatch');
  }

  // --- Step 9: ok ---
  return { result: { valid: true, reason: 'ok' }, decoded: { payloadBytes: payloadBuf, payload } };
}
