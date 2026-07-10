package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	vitni "github.com/Daily-Nerd/vitni/go"
)

// RFC 8032 §7.1 TEST 1 — published constants, the cross-impl anchor.
const (
	rfcSeedB64 = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="
	rfcPubX    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

type keygenJwk struct {
	Alg    string `json:"alg"`
	Crv    string `json:"crv"`
	Kty    string `json:"kty"`
	Status string `json:"status"`
	X      string `json:"x"`
}

type keygenOut struct {
	Jwk           keygenJwk `json:"jwk"`
	PrivateKeyB64 string    `json:"private_key_b64"`
}

func mustKeygen(t *testing.T, stdin string) keygenOut {
	t.Helper()
	raw, err := runKeygen([]byte(stdin))
	if err != nil {
		t.Fatalf("runKeygen(%s): %v", stdin, err)
	}
	var out keygenOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	return out
}

func TestKeygen_DeriveFromSeed(t *testing.T) {
	out := mustKeygen(t, `{"seed_b64":"`+rfcSeedB64+`"}`)
	want := keygenJwk{Alg: "EdDSA", Crv: "Ed25519", Kty: "OKP", Status: "active", X: rfcPubX}
	if out.Jwk != want {
		t.Errorf("jwk = %+v, want %+v", out.Jwk, want)
	}
	if out.PrivateKeyB64 != rfcSeedB64 {
		t.Errorf("private_key_b64 = %q, want the input seed back", out.PrivateKeyB64)
	}
}

func TestKeygen_DeriveFromUnpaddedSeed(t *testing.T) {
	// Same seed without '=' padding must derive identically (flexible base64).
	out := mustKeygen(t, `{"seed_b64":"`+strings.TrimRight(rfcSeedB64, "=")+`"}`)
	if out.Jwk.X != rfcPubX {
		t.Errorf("x = %q, want %q", out.Jwk.X, rfcPubX)
	}
}

func TestKeygen_Errors(t *testing.T) {
	tests := []struct {
		name     string
		stdin    string
		wantSeed bool // true: errors.Is(err, errInvalidSeed); false: any other non-nil error (maps to invalid_input)
	}{
		{name: "empty string seed is an error, never generate", stdin: `{"seed_b64":""}`, wantSeed: true},
		{name: "wrong length (16 bytes)", stdin: `{"seed_b64":"AQIDBAUGBwgJCgsMDQ4PEA=="}`, wantSeed: true},
		{name: "malformed base64", stdin: `{"seed_b64":"!!!not-base64!!!"}`, wantSeed: true},
		{name: "null seed value", stdin: `{"seed_b64":null}`, wantSeed: true},
		{name: "non-string seed (number)", stdin: `{"seed_b64":123}`, wantSeed: true},
		{name: "unknown top-level key", stdin: `{"seed_b64":"` + rfcSeedB64 + `","kid":"x"}`, wantSeed: false},
		{name: "non-object input", stdin: `[1,2]`, wantSeed: false},
		{name: "json null input", stdin: `null`, wantSeed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runKeygen([]byte(tt.stdin))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := errors.Is(err, errInvalidSeed); got != tt.wantSeed {
				t.Errorf("errors.Is(err, errInvalidSeed) = %v, want %v (err=%v)", got, tt.wantSeed, err)
			}
		})
	}
}

func TestKeygen_RandomPath(t *testing.T) {
	a := mustKeygen(t, `{}`)
	b := mustKeygen(t, `{}`)
	if a.PrivateKeyB64 == b.PrivateKeyB64 || a.Jwk.X == b.Jwk.X {
		t.Error("two {} invocations returned identical key material")
	}
	// Structural: derived jwk must equal a re-derivation from the emitted seed.
	rederived := mustKeygen(t, `{"seed_b64":"`+a.PrivateKeyB64+`"}`)
	if rederived.Jwk.X != a.Jwk.X {
		t.Errorf("re-derive from emitted seed: x = %q, want %q", rederived.Jwk.X, a.Jwk.X)
	}
}

// signWith signs the sign-ed25519.json vector's receipt body with the given seed
// via runSign, returning the compact JWS.
func signWith(t *testing.T, seedB64 string) string {
	t.Helper()
	receipt := `{"v":"vitni/0.2","binding":"mcp","action_ref":null,"performer_id":"srv-ed","requester_id":null,"method":"mcp:echo","inputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","outputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","cost":{"tokens":"10","usd_micros":"0","wall_ms":"3","rail_ref":null},"status":"OK","reason":null,"parent_receipt_hash":null,"log_policy":"best_effort","ts":"2026-05-28T00:00:00Z","nonce":"uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ"}`
	raw, err := runSign([]byte(`{"receipt":` + receipt + `,"kid":"ed-1","private_key_b64":"` + seedB64 + `"}`))
	if err != nil {
		t.Fatalf("runSign: %v", err)
	}
	var out struct {
		SignedReceipt string `json:"signed_receipt"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse sign output: %v", err)
	}
	return out.SignedReceipt
}

func verifyAgainst(t *testing.T, signed string, jwk keygenJwk) (bool, string) {
	t.Helper()
	jwkJSON, _ := json.Marshal(jwk)
	inputJSON := `{"signed_receipt":"` + signed + `","keys":{"srv-ed":{"ed-1":` + string(jwkJSON) + `}}}`
	var vi vitni.VerifyInput
	if err := json.Unmarshal([]byte(inputJSON), &vi); err != nil {
		t.Fatalf("build VerifyInput: %v", err)
	}
	return vitni.Verify(vi)
}

func TestKeygen_RoundTrip(t *testing.T) {
	out := mustKeygen(t, `{"seed_b64":"`+rfcSeedB64+`"}`)
	signed := signWith(t, rfcSeedB64)
	valid, reason := verifyAgainst(t, signed, out.Jwk)
	if !valid || reason != "ok" {
		t.Errorf("round-trip verify = (%v, %q), want (true, \"ok\")", valid, reason)
	}
}

func TestKeygen_NegativeBinding(t *testing.T) {
	// jwk from seed A, signature from seed B → MUST fail. Guards against a
	// keygen that echoes any structurally-valid key.
	out := mustKeygen(t, `{"seed_b64":"`+rfcSeedB64+`"}`)
	signed := signWith(t, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=") // seed B (the sign vector's seed)
	valid, reason := verifyAgainst(t, signed, out.Jwk)
	if valid {
		t.Fatal("verify accepted a signature from a different key")
	}
	if reason != "bad_signature" {
		t.Errorf("reason = %q, want \"bad_signature\"", reason)
	}
}
