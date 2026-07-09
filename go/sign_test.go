package vitni_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Daily-Nerd/vitni/go"
)

// TestSign_RoundTripsWithVerify proves the public Sign API produces a JWS that
// the public Verify API accepts under the matching registry key.
func TestSign_RoundTripsWithVerify(t *testing.T) {
	// Deterministic Ed25519 keypair from a fixed 32-byte seed.
	seed := []byte("veritrail-test-ed25519-seed-32by")
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed size = %d, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	r := vitni.Receipt{
		Binding:     "mcp",
		PerformerID: "srv-test",
		Method:      "mcp:echo",
		InputsHash:  "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
		OutputsHash: "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
		Cost: vitni.Cost{
			Tokens: "10", USDMicros: "0", WallMs: "3",
		},
		Status:    "OK",
		LogPolicy: "best_effort",
		Ts:        "2026-05-28T00:00:00Z",
		Nonce:     "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",
	}

	jws, err := vitni.Sign(r, "ed-1", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// JWS must have three segments.
	if n := len(strings.Split(jws, ".")); n != 3 {
		t.Fatalf("JWS segments = %d, want 3", n)
	}

	// The signed payload must carry the new version string.
	parts := strings.Split(jws, ".")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload["v"] != vitni.Version {
		t.Errorf("payload v = %v, want %s", payload["v"], vitni.Version)
	}
	if vitni.Version != "vitni/0.2" {
		t.Errorf("Version const = %q, want vitni/0.2", vitni.Version)
	}
	if vitni.MCPMetaKey != "dev.vitni/receipt" {
		t.Errorf("MCPMetaKey const = %q, want dev.vitni/receipt", vitni.MCPMetaKey)
	}

	// Verify must accept it.
	in := vitni.VerifyInput{
		SignedReceipt: jws,
		Keys: map[string]map[string]vitni.RegistryKey{
			"srv-test": {
				"ed-1": {
					Kty:    "OKP",
					Crv:    "Ed25519",
					X:      base64.RawURLEncoding.EncodeToString(pub),
					Alg:    "EdDSA",
					Status: "active",
				},
			},
		},
	}
	valid, reason := vitni.Verify(in)
	if !valid || reason != "ok" {
		t.Errorf("Verify(signed) = (%v, %q), want (true, ok)", valid, reason)
	}
}
