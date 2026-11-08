/**
 * verify-chain command — full lineage-path verification (design §7, §12 step 9).
 *
 * `receipts` is an ordered leaf→root path (index 0 = leaf, last = root).
 *
 * Algorithm (first-failing-check-wins, in THIS order):
 *  1. empty_chain              — receipts is empty.
 *  2. receipt_invalid          — run full §7 verify on EVERY hop. policy applies to
 *                                the leaf (i=0) only; other hops use an empty policy.
 *  3. (compute receipt_id[i] = "u"+base64url(multihash sha256(JCS(payload_i)))).
 *  4. malformed_chain          — a non-root hop (i < n-1) has parent_receipt_hash == null,
 *                                OR the root hop (i = n-1) has parent_receipt_hash != null.
 *  5. link_mismatch            — for any i < n-1, receipts[i].parent_receipt_hash != receipt_id[i+1].
 *  6. parent_identity_mismatch — for any i < n-1 where receipts[i].parent_performer_id is
 *                                present & non-null, it != receipts[i+1].performer_id.
 *  7. cycle                    — any receipt_id value appears more than once.
 *  8. ok.
 *
 * Output: { valid, reason, chain_len } as JCS-canonical JSON (CLI applies JCS).
 */
import { verify, RegistryJwk } from './verify.js';
import { jcsBytes } from './jcs.js';
import { digestBytes } from './digest.js';
import { decodeB64UrlStrict } from './decode.js';

export interface VerifyChainInput {
  receipts: string[];
  keys: Record<string, Record<string, RegistryJwk>>;
  policy?: {
    expected_binding?: string | null;
    expected_method?: string | null;
  };
}

export interface VerifyChainOutput {
  valid: boolean;
  reason: string;
  chain_len: number;
}

const EMPTY_POLICY = { expected_binding: null, expected_method: null };

function fail(reason: string, chainLen: number): VerifyChainOutput {
  return { valid: false, reason, chain_len: chainLen };
}

/**
 * Parse the payload of a compact JWS. Returns the payload object, or null if it
 * cannot be parsed. Used only AFTER §7 verify has passed for the hop, so the
 * payload is guaranteed to be valid base64url + valid UTF-8 + valid JSON object.
 */
function parsePayload(jws: string): Record<string, unknown> | null {
  const parts = jws.split('.');
  if (parts.length !== 3) return null;
  try {
    const buf = decodeB64UrlStrict(parts[1]);
    if (buf === null) return null;
    const obj = JSON.parse(buf.toString('utf8'));
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return null;
    return obj as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * receipt_id = "u" + base64url(multihash sha256(JCS(payload))).
 * Identical to the §2/§4.1 / §7 receipt-id computation.
 */
function computeReceiptId(payload: Record<string, unknown>): string {
  return digestBytes(jcsBytes(payload));
}

export function verifyChain(input: VerifyChainInput): VerifyChainOutput {
  const receipts = input.receipts;

  // --- Step 1: empty_chain ---
  if (!Array.isArray(receipts) || receipts.length === 0) {
    return fail('empty_chain', 0);
  }
  const n = receipts.length;

  // --- Step 2: receipt_invalid (run §7 verify on every hop) ---
  // policy applies to the leaf (i=0) only; other hops use an empty policy.
  for (let i = 0; i < n; i++) {
    const hopPolicy = i === 0 ? input.policy ?? EMPTY_POLICY : EMPTY_POLICY;
    const res = verify({
      signed_receipt: receipts[i],
      keys: input.keys,
      policy: hopPolicy,
    });
    if (!res.valid) {
      return fail('receipt_invalid', n);
    }
  }

  // --- Step 3: compute receipt_id and parse payloads ---
  // Every hop passed §7, so payloads are valid and re-parsing is safe.
  const payloads: Record<string, unknown>[] = [];
  const receiptIds: string[] = [];
  for (let i = 0; i < n; i++) {
    const payload = parsePayload(receipts[i]);
    if (payload === null) {
      // Should be unreachable given step 2 passed, but be defensive.
      return fail('receipt_invalid', n);
    }
    payloads.push(payload);
    receiptIds.push(computeReceiptId(payload));
  }

  // --- Step 4: malformed_chain ---
  for (let i = 0; i < n; i++) {
    const parentHash = payloads[i]['parent_receipt_hash'];
    const isRoot = i === n - 1;
    if (!isRoot) {
      // non-root hop must have a non-null parent
      if (parentHash === null || parentHash === undefined) {
        return fail('malformed_chain', n);
      }
    } else {
      // root hop must have a null parent (no claimed-but-unprovided parent)
      if (parentHash !== null && parentHash !== undefined) {
        return fail('malformed_chain', n);
      }
    }
  }

  // --- Step 5: link_mismatch ---
  for (let i = 0; i < n - 1; i++) {
    if (payloads[i]['parent_receipt_hash'] !== receiptIds[i + 1]) {
      return fail('link_mismatch', n);
    }
  }

  // --- Step 6: parent_identity_mismatch ---
  for (let i = 0; i < n - 1; i++) {
    const claimedParentPerf = payloads[i]['parent_performer_id'];
    if (claimedParentPerf !== null && claimedParentPerf !== undefined) {
      if (claimedParentPerf !== payloads[i + 1]['performer_id']) {
        return fail('parent_identity_mismatch', n);
      }
    }
  }

  // --- Step 7: cycle ---
  const seen = new Set<string>();
  for (const id of receiptIds) {
    if (seen.has(id)) {
      return fail('cycle', n);
    }
    seen.add(id);
  }

  // --- Step 8: ok ---
  return { valid: true, reason: 'ok', chain_len: n };
}
