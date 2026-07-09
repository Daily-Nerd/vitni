package vitni_test

import (
	"encoding/json"
	"testing"

	"github.com/Daily-Nerd/vitni/go"
)

// TestVectors_VerifyChain drives the verify-chain command against every chain-*.json vector.
func TestVectors_VerifyChain(t *testing.T) {
	count := 0
	for _, v := range loadVectors(t) {
		if v.Command != "verify-chain" {
			continue
		}
		count++
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp vitni.VerifyChainInput
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatalf("unmarshal input: %v", err)
			}
			valid, reason, chainLen := vitni.VerifyChain(inp)

			var anchor struct {
				Valid    bool   `json:"valid"`
				Reason   string `json:"reason"`
				ChainLen int    `json:"chain_len"`
			}
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatalf("unmarshal anchor: %v", err)
			}
			if valid != anchor.Valid {
				t.Errorf("valid = %v, want %v (reason got %q want %q)", valid, anchor.Valid, reason, anchor.Reason)
			}
			if reason != anchor.Reason {
				t.Errorf("reason = %q, want %q", reason, anchor.Reason)
			}
			if chainLen != anchor.ChainLen {
				t.Errorf("chain_len = %d, want %d", chainLen, anchor.ChainLen)
			}
		})
	}
	if count == 0 {
		t.Fatal("no verify-chain vectors found")
	}
}

// TestVerifyChain_Empty checks the first step (empty_chain).
func TestVerifyChain_Empty(t *testing.T) {
	inp := vitni.VerifyChainInput{
		Receipts: []string{},
		Keys:     map[string]map[string]vitni.RegistryKey{},
	}
	valid, reason, n := vitni.VerifyChain(inp)
	if valid || reason != "empty_chain" || n != 0 {
		t.Errorf("got (%v, %q, %d), want (false, empty_chain, 0)", valid, reason, n)
	}
}
