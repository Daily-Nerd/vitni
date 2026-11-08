package vitni_test

import (
	"encoding/json"
	"testing"

	"github.com/Daily-Nerd/vitni/go"
	"github.com/Daily-Nerd/vitni/go/internal/wire"
)

// TestVectors_Verify drives the verify command against every verify-*.json vector.
func TestVectors_Verify(t *testing.T) {
	count := 0
	for _, v := range loadLibraryVectors(t) {
		if v.Command != "verify" {
			continue
		}
		count++
		v := v
		t.Run(v.Name, func(t *testing.T) {
			// The wire decoder is the one the CLI uses: member names are exact
			// and wrong types are errors. An `error` anchor is a command error.
			inp, err := wire.DecodeVerifyInput(v.Input)
			if isErrorVector(t, v.Anchor) {
				if err == nil {
					t.Fatalf("expected a decode error for anchor %s, got none", v.Anchor)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode input: %v", err)
			}
			valid, reason := vitni.Verify(inp)

			var anchor struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
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
		})
	}
	if count == 0 {
		t.Fatal("no verify vectors found")
	}
}

// TestVerify_MalformedNotThreeSegments checks the first-failing-check (malformed).
func TestVerify_MalformedNotThreeSegments(t *testing.T) {
	inp := vitni.VerifyInput{
		SignedReceipt: "onlyonesegment",
		Keys:          map[string]map[string]vitni.RegistryKey{},
	}
	valid, reason := vitni.Verify(inp)
	if valid || reason != "malformed" {
		t.Errorf("got (%v, %q), want (false, malformed)", valid, reason)
	}
}

// TestVerify_MalformedBadJSONHeader checks malformed when header is not JSON.
func TestVerify_MalformedBadJSONHeader(t *testing.T) {
	// "notjson" base64url => header decodes to bytes that are not JSON
	inp := vitni.VerifyInput{
		// b64url("xx").b64url("{}").sig
		SignedReceipt: "eHg.e30.AAAA",
		Keys:          map[string]map[string]vitni.RegistryKey{},
	}
	valid, reason := vitni.Verify(inp)
	if valid || reason != "malformed" {
		t.Errorf("got (%v, %q), want (false, malformed)", valid, reason)
	}
}

// TestSupportedAlgs pins the algorithm table: it is the single owner of
// {alg -> kty, crv, verify fn}, and the declared alg set derives from it, so it
// cannot drift from what Verify accepts.
func TestSupportedAlgs(t *testing.T) {
	got := vitni.SupportedAlgs()
	want := []string{"ES256", "EdDSA"} // sorted by code point
	if len(got) != len(want) {
		t.Fatalf("SupportedAlgs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SupportedAlgs() = %v, want %v", got, want)
		}
	}
}
