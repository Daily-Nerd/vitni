/**
 * Vitni co-signing middleware for A2A (design §14).
 *
 * On Task completion, build a Vitni Receipt with:
 *   - binding: "a2a"
 *   - method:  "a2a:<skill>"
 *   - outputs_hash: the §9 artifact-hash over the Task artifact's parts.
 *   - inputs_hash:  the §9 artifact-hash over the request message's parts.
 * Sign it (EdDSA JWS, reusing the §7/MCP signing path) and attach the compact JWS
 * to the artifact at artifact.metadata["dev.veritrail/receipt"].
 *
 * A2A artifact.metadata is a {[k:string]: unknown} passthrough map (SDK type), so
 * a namespaced receipt key is preserved through serialization and ignored by
 * consumers that don't know about Vitni.
 */
import { randomBytes } from 'node:crypto';
import {
  TestSigner,
  signReceipt,
  RECEIPT_META_KEY,
} from '../mcp/vitni-middleware.js';
import { a2aArtifactHash } from '../commands/a2a-artifact-hash.js';
import { VERSION } from '../version.js';

export { RECEIPT_META_KEY };

/** Minimal A2A Part shape (text | data | file) used for hashing. */
export interface A2APartLike {
  kind: string;
  text?: unknown;
  data?: unknown;
  file?: { bytes?: string; uri?: string; declared_digest?: string | null; mimeType?: string | null; name?: string | null };
}

/** Minimal A2A artifact shape we co-sign. */
export interface A2AArtifactLike {
  artifactId?: string;
  name?: string;
  parts: A2APartLike[];
  metadata?: Record<string, unknown>;
}

/**
 * Compute the §9 outputs_hash over an A2A artifact's parts. Throws if any part is
 * unsupported (the middleware should only co-sign well-formed artifacts).
 */
export function computeArtifactHash(parts: A2APartLike[]): string {
  const res = a2aArtifactHash({ artifact: { parts } });
  if ('error' in res) {
    throw new Error(`cannot co-sign artifact: ${res.error}`);
  }
  return res.outputs_hash;
}

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

export interface BuildA2AReceiptOptions {
  signer: TestSigner;
  skill: string;
  /** The request message parts (for inputs_hash). */
  requestParts: A2APartLike[];
  /** The result artifact parts (for outputs_hash). */
  artifactParts: A2APartLike[];
  ts?: string;
  wallMs?: string;
}

/** Build the Vitni Receipt payload for an A2A task. */
export function buildA2AReceiptPayload(opts: BuildA2AReceiptOptions): Record<string, unknown> {
  return {
    v: VERSION,
    binding: 'a2a',
    action_ref: null,
    performer_id: opts.signer.performerId,
    requester_id: null,
    parent_performer_id: null,
    parent_receipt_hash: null,
    method: `a2a:${opts.skill}`,
    inputs_hash: computeArtifactHash(opts.requestParts),
    outputs_hash: computeArtifactHash(opts.artifactParts),
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
 * Co-sign an A2A artifact in place: build + sign the receipt and attach it at
 * artifact.metadata["dev.veritrail/receipt"]. Returns the same artifact.
 */
export function vitniArtifact(
  artifact: A2AArtifactLike,
  opts: { signer: TestSigner; skill: string; requestParts: A2APartLike[]; ts?: string; wallMs?: string }
): A2AArtifactLike {
  const payload = buildA2AReceiptPayload({
    signer: opts.signer,
    skill: opts.skill,
    requestParts: opts.requestParts,
    artifactParts: artifact.parts,
    ts: opts.ts,
    wallMs: opts.wallMs,
  });
  const jws = signReceipt(payload, opts.signer);
  artifact.metadata = { ...(artifact.metadata ?? {}), [RECEIPT_META_KEY]: jws };
  return artifact;
}
