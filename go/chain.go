package vitni

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

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
	for i, jws := range in.Receipts {
		vi := VerifyInput{
			SignedReceipt: jws,
			Keys:          in.Keys,
		}
		if i == 0 {
			vi.Policy = in.Policy
		}
		if ok, _ := Verify(vi); !ok {
			return false, "receipt_invalid", n
		}
	}

	// --- Step 3: compute receipt_id[i] for each hop ---
	// Every hop passed §7 verify, so its payload is valid canonical JSON; the raw
	// payload bytes therefore equal JCS(payload) and receipt_id = Digest(bytes).
	receiptIDs := make([]string, n)
	payloads := make([]map[string]json.RawMessage, n)
	for i, jws := range in.Receipts {
		payloadBytes, payload, ok := decodePayload(jws)
		if !ok {
			// Unreachable in practice: §7 verify already guaranteed a valid payload.
			return false, "receipt_invalid", n
		}
		rid, err := Digest(payloadBytes)
		if err != nil {
			return false, "receipt_invalid", n
		}
		receiptIDs[i] = rid
		payloads[i] = payload
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
			continue
		}
		ppid := stringClaim(payloads[i], "parent_performer_id")
		if ppid == "" {
			// present but not a string / absent — treat as no constraint.
			continue
		}
		if ppid != stringClaim(payloads[i+1], "performer_id") {
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

// decodePayload splits a JWS compact string and returns the raw payload bytes
// plus the parsed payload object. ok=false if structure/JSON is invalid.
func decodePayload(jws string) ([]byte, map[string]json.RawMessage, bool) {
	segs := strings.Split(jws, ".")
	if len(segs) != 3 {
		return nil, nil, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return nil, nil, false
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, false
	}
	return payloadBytes, payload, true
}

// claimIsNull reports whether a claim is absent OR explicitly JSON null.
func claimIsNull(m map[string]json.RawMessage, key string) bool {
	raw, ok := m[key]
	if !ok {
		return true
	}
	return string(raw) == "null"
}
