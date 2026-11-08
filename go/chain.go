package vitni

import "encoding/json"

// VerifyChainInput is the input object for the verify-chain command.
type VerifyChainInput struct {
	Receipts []string                          `json:"receipts"`
	Keys     map[string]map[string]RegistryKey `json:"keys"`
	Policy   VerifyPolicy                      `json:"policy"`
}

// VerifyChain runs the §8 lineage-path verification algorithm. First failing
// check wins, in the documented order. Returns (valid, reasonCode, chainLen).
func VerifyChain(in VerifyChainInput) (bool, string, int) {
	n := len(in.Receipts)

	// --- Step 1: empty_chain ---
	if n == 0 {
		return false, "empty_chain", 0
	}

	// --- Step 2: receipt_invalid (run §7 verify on every hop) ---
	// policy applies to the leaf (i=0) only; all other hops use an empty policy.
	// Each accepted hop hands back its decoded payload, so nothing is decoded twice.
	receiptIDs := make([]string, n)
	payloads := make([]map[string]json.RawMessage, n)
	for i, jws := range in.Receipts {
		vi := VerifyInput{
			SignedReceipt: jws,
			Keys:          in.Keys,
		}
		if i == 0 {
			vi.Policy = in.Policy
		}
		reason, hop := verifyDecoded(vi)
		if reason != "ok" {
			return false, "receipt_invalid", n
		}
		// --- Step 3: receipt_id[i] ---
		// The hop passed §7 verify, so its payload is valid canonical JSON: the raw
		// payload bytes equal JCS(payload) and receipt_id = Digest(bytes).
		receiptIDs[i] = digestString(hop.bytes)
		payloads[i] = hop.object
	}

	// --- Step 4: malformed_chain ---
	// non-root hop with null parent, OR root hop with non-null parent.
	for i := 0; i < n; i++ {
		parentNull := claimIsNull(payloads[i], "parent_receipt_hash")
		isRoot := i == n-1
		if !isRoot && parentNull {
			return false, "malformed_chain", n
		}
		if isRoot && !parentNull {
			return false, "malformed_chain", n
		}
	}

	// --- Step 5: link_mismatch ---
	for i := 0; i < n-1; i++ {
		parentHash := stringClaim(payloads[i], "parent_receipt_hash")
		if parentHash != receiptIDs[i+1] {
			return false, "link_mismatch", n
		}
	}

	// --- Step 6: parent_identity_mismatch ---
	for i := 0; i < n-1; i++ {
		if claimIsNull(payloads[i], "parent_performer_id") {
			continue // absent or explicit null → no lineage-identity claim (§7)
		}
		// A present (non-null) parent_performer_id is a CARRIED claim (DESIGN §7
		// point 4) and MUST equal the parent's performer_id. An empty string or a
		// non-string is still carried — stringClaim renders both as "", which
		// cannot match a real performer_id, so the splice is rejected. (Treating
		// an empty string as "no constraint" would let a spliced parent pass.)
		if stringClaim(payloads[i], "parent_performer_id") != stringClaim(payloads[i+1], "performer_id") {
			return false, "parent_identity_mismatch", n
		}
	}

	// --- Step 7: cycle ---
	seen := make(map[string]bool, n)
	for _, rid := range receiptIDs {
		if seen[rid] {
			return false, "cycle", n
		}
		seen[rid] = true
	}

	// --- Step 8: ok ---
	return true, "ok", n
}

// claimIsNull reports whether a claim is absent OR explicitly JSON null.
func claimIsNull(m map[string]json.RawMessage, key string) bool {
	raw, ok := m[key]
	if !ok {
		return true
	}
	return string(raw) == "null"
}
