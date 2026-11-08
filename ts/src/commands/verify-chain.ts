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
import { verifyDecoded, RegistryJwk } from './verify.js';
import { digestBytes } from './digest.js';

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

export function verifyChain(input: VerifyChainInput): VerifyChainOutput {
  const receipts = input.receipts;

  // --- Step 1: empty_chain ---
  if (!Array.isArray(receipts) || receipts.length === 0) {
    return fail('empty_chain', 0);
  }
  const n = receipts.length;

  // --- Step 2: receipt_invalid (run §7 verify on every hop) ---
  // policy applies to the leaf (i=0) only; other hops use an empty policy.
  // Each accepted hop hands back its decoded payload, so nothing is decoded twice.
  const payloads: Record<string, unknown>[] = [];
  const receiptIds: string[] = [];
  for (let i = 0; i < n; i++) {
    const hopPolicy = i === 0 ? input.policy ?? EMPTY_POLICY : EMPTY_POLICY;
    const { decoded } = verifyDecoded({
      signed_receipt: receipts[i],
      keys: input.keys,
      policy: hopPolicy,
    });
    if (decoded === null) {
      return fail('receipt_invalid', n);
    }
    // --- Step 3: receipt_id[i] ---
    // The hop passed §7, so its payload bytes equal JCS(payload).
    payloads.push(decoded.payload);
    receiptIds.push(digestBytes(decoded.payloadBytes));
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
