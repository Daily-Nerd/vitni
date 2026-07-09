/**
 * Vitni co-signing middleware for MCP (design §13).
 *
 * Given an MCP tool call (toolName, params, result), build a Vitni Receipt:
 *   - binding: "mcp"
 *   - method:  "mcp:<toolName>"
 *   - inputs_hash  = "u" + multihash(sha256(JCS(params)))
 *   - outputs_hash = "u" + multihash(sha256(JCS(result EXCLUDING _meta)))
 *   - plus the standard Receipt fields.
 *
 * The receipt is signed (Ed25519 / EdDSA JWS, payload = JCS-canonical octets so it
 * round-trips through §7 verify with no non_canonical_payload failure) and attached
 * to the MCP result at result._meta["dev.veritrail/receipt"].
 *
 * A client that ignores _meta is entirely unaffected — the receipt is additive.
 */
import {
  generateKeyPairSync,
  sign as cryptoSign,
  randomBytes,
  KeyObject,
} from 'node:crypto';
import { jcsBytes, jcsString } from '../commands/jcs.js';
import { digestBytes } from '../commands/digest.js';
import type { RegistryJwk } from '../commands/verify.js';
import { VERSION } from '../version.js';

/** The _meta key the receipt JWS is published under (design §13). */
export const RECEIPT_META_KEY = 'dev.veritrail/receipt';

/** A test signer: an Ed25519 private key plus its registry identity. */
export interface TestSigner {
  privateKey: KeyObject;
  /** Public JWK (kty/crv/x/alg/status) as published in the key registry. */
  publicJwk: RegistryJwk;
  performerId: string;
  kid: string;
}

/** Minimal shape of an MCP CallTool result we co-sign over. */
export interface McpResultLike {
  _meta?: Record<string, unknown>;
  [k: string]: unknown;
}

/**
 * Generate a fresh Ed25519 test signer with a fixed performer_id / kid.
 * The public key is exported as a JWK suitable for the §7 key registry.
 */
export function generateTestSigner(
  performerId = 'srv-mcp-demo',
  kid = 'ed-demo-1'
): TestSigner {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
  return {
    privateKey,
    publicJwk: {
      kty: jwk.kty, // "OKP"
      crv: jwk.crv, // "Ed25519"
      x: jwk.x,
      alg: 'EdDSA',
      status: 'active',
    },
    performerId,
    kid,
  };
}

/** Build a §7 key registry { performer_id: { kid: jwk } } from a signer. */
export function registryFromSigner(
  signer: TestSigner
): Record<string, Record<string, RegistryJwk>> {
  return { [signer.performerId]: { [signer.kid]: signer.publicJwk } };
}

/** base64url (no padding) of a buffer. */
function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

/**
 * The hash-string of a value's JCS octets: "u" + multihash(sha256(JCS(value))).
 * Used for inputs_hash and outputs_hash.
 */
export function hashOf(value: unknown): string {
  return digestBytes(jcsBytes(value));
}

/**
 * Strip the _meta envelope from a result before hashing. The receipt itself lives
 * under _meta, so it must be excluded from outputs_hash (a receipt cannot commit to
 * its own bytes). design §13.
 */
export function stripMeta(result: McpResultLike): Record<string, unknown> {
  const { _meta, ...rest } = result;
  void _meta;
  return rest;
}

/** outputs_hash over a result, excluding _meta. */
export function computeOutputsHash(result: McpResultLike): string {
  return hashOf(stripMeta(result));
}

export interface BuildReceiptOptions {
  signer: TestSigner;
  toolName: string;
  params: unknown;
  result: McpResultLike;
  /** Fixed timestamp for deterministic demos. */
  ts?: string;
  /** Measured wall time in ms (string-encoded integer per §2). */
  wallMs?: string;
}

/**
 * Build the Vitni Receipt payload object (without receipt_id — that is a content
 * address derived from this object). Field order is irrelevant; JCS sorts on signing.
 */
export function buildReceiptPayload(opts: BuildReceiptOptions): Record<string, unknown> {
  const { signer, toolName, params, result } = opts;
  return {
    v: VERSION,
    binding: 'mcp',
    action_ref: null,
    performer_id: signer.performerId,
    requester_id: null,
    parent_performer_id: null,
    parent_receipt_hash: null,
    method: `mcp:${toolName}`,
    inputs_hash: hashOf(params),
    outputs_hash: computeOutputsHash(result),
    cost: {
      tokens: '0',
      usd_micros: '0',
      wall_ms: opts.wallMs ?? '0',
      rail_ref: null,
    },
    status: 'OK',
    reason: null,
    log_policy: 'best_effort',
    ts: opts.ts ?? '2026-05-28T00:00:00Z',
    nonce: 'u' + b64url(randomBytes(16)),
  };
}

/**
 * Sign a receipt payload as a compact EdDSA JWS.
 *
 * The payload segment is the JCS-canonical octets of the receipt, so §7 verify
 * passes the non_canonical_payload check. The signing input is the ASCII
 * b64url(header).b64url(payload), matching the verifier.
 */
export function signReceipt(payload: Record<string, unknown>, signer: TestSigner): string {
  const header = { alg: 'EdDSA', kid: signer.kid };
  const headerSeg = b64url(Buffer.from(jcsString(header), 'utf8'));
  // payload MUST be canonical so verify() does not reject it as non_canonical_payload
  const payloadSeg = b64url(jcsBytes(payload));
  const signingInput = Buffer.from(`${headerSeg}.${payloadSeg}`, 'ascii');
  const sig = cryptoSign(null, signingInput, signer.privateKey);
  return `${headerSeg}.${payloadSeg}.${b64url(sig)}`;
}

/**
 * The full middleware step: given a tool call and its result, build + sign the
 * receipt and attach it to result._meta["dev.veritrail/receipt"]. Returns the same
 * result object (mutated) for convenience.
 */
export function vitniToolResult(opts: BuildReceiptOptions): McpResultLike {
  const payload = buildReceiptPayload(opts);
  const jws = signReceipt(payload, opts.signer);
  const result = opts.result;
  result._meta = { ...(result._meta ?? {}), [RECEIPT_META_KEY]: jws };
  return result;
}
