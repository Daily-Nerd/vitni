package vitni_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Daily-Nerd/vitni/go"
)

// vectorFile represents a test vector loaded from disk.
type vectorFile struct {
	Name    string          `json:"name"`
	Command string          `json:"command"`
	Input   json.RawMessage `json:"input"`
	Anchor  json.RawMessage `json:"anchor"`
}

// loadVectors loads all *.json files from the vectors directory relative to the module root.
func loadVectors(t *testing.T) []vectorFile {
	t.Helper()
	// vectors live under conformance/vectors at the repo root;
	// this package dir is the module root (go/), so go up one then into conformance/vectors.
	dir := filepath.Join("..", "conformance", "vectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read vectors dir %s: %v", dir, err)
	}
	var vecs []vectorFile
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var v vectorFile
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		vecs = append(vecs, v)
	}
	return vecs
}

// isErrorVector reports whether a vector's anchor asserts an error, i.e. it is
// a negative (malformed-input) vector rather than a happy-path one.
func isErrorVector(t *testing.T, anchor json.RawMessage) bool {
	t.Helper()
	var a map[string]json.RawMessage
	if err := json.Unmarshal(anchor, &a); err != nil {
		return false
	}
	_, ok := a["error"]
	return ok
}

// assertBase64Rejected fails unless the input is rejected by BOTH standard
// base64 decoders — the exact condition under which the CLI (main.go) returns
// invalid_input. Used for negative vectors whose rejection lives at the CLI
// decode layer, not in the library.
func assertBase64Rejected(t *testing.T, s string) {
	t.Helper()
	_, e1 := base64.StdEncoding.DecodeString(s)
	_, e2 := base64.RawStdEncoding.DecodeString(s)
	if e1 == nil || e2 == nil {
		t.Fatalf("expected base64 rejection, but a decoder accepted %q", s)
	}
}

// -------------------------------------------------------------------
// Unit tests for JCS
// -------------------------------------------------------------------

func TestJCS_SortedKeys(t *testing.T) {
	input := json.RawMessage(`{"b":1,"a":2}`)
	got, err := vitni.JCS(input)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1}`
	if string(got) != want {
		t.Errorf("JCS = %q, want %q", got, want)
	}
}

func TestJCS_NestedAndUnicode(t *testing.T) {
	// "é" is U+00E9, encoded in UTF-8 as 0xC3 0xA9
	input := json.RawMessage(`{"z":"é","a":[3,1,2]}`)
	got, err := vitni.JCS(input)
	if err != nil {
		t.Fatal(err)
	}
	wantHex := "7b2261223a5b332c312c325d2c227a223a22c3a9227d"
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("JCS hex = %s, want %s", hex.EncodeToString(got), wantHex)
	}
}

// -------------------------------------------------------------------
// Unit tests for HashString
// -------------------------------------------------------------------

func TestHashString_KnownDigest(t *testing.T) {
	// sha256 of "hello" is well-known
	digestHex := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	got, err := vitni.HashString(digestHex)
	if err != nil {
		t.Fatal(err)
	}
	// Verify it starts with "u"
	if len(got) == 0 || got[0] != 'u' {
		t.Errorf("HashString = %q, want leading 'u'", got)
	}
	// Verify decodable base64url
	b, err := base64.RawURLEncoding.DecodeString(got[1:])
	if err != nil {
		t.Fatalf("base64url decode failed: %v", err)
	}
	// First two bytes must be 0x12, 0x20 (sha2-256 varint code, varint len=32)
	if len(b) < 2 || b[0] != 0x12 || b[1] != 0x20 {
		t.Errorf("multihash prefix = %x, want 1220", b[:2])
	}
}

// -------------------------------------------------------------------
// Unit tests for Digest
// -------------------------------------------------------------------

func TestDigest_Empty(t *testing.T) {
	got, err := vitni.Digest([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	want := "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ"
	if got != want {
		t.Errorf("Digest(empty) = %q, want %q", got, want)
	}
}

func TestDigest_Hello(t *testing.T) {
	got, err := vitni.Digest([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	want := "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA"
	if got != want {
		t.Errorf("Digest(hello) = %q, want %q", got, want)
	}
}

// -------------------------------------------------------------------
// Unit tests for SSE decode
// -------------------------------------------------------------------

func TestSSEDecode_TwoDataOneEvent(t *testing.T) {
	// data: hello\ndata: world\n\n  -> "hello\nworld"
	raw := []byte("data: hello\ndata: world\n\n")
	msgs, err := vitni.SSEDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("SSEDecode: got %d messages, want 1", len(msgs))
	}
	if msgs[0] != "hello\nworld" {
		t.Errorf("SSEDecode: msg = %q, want %q", msgs[0], "hello\nworld")
	}
}

func TestSSEDecode_TwoEvents(t *testing.T) {
	raw := []byte("data: a\n\ndata: b\n\n")
	msgs, err := vitni.SSEDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("SSEDecode: got %d messages, want 2", len(msgs))
	}
	if msgs[0] != "a" || msgs[1] != "b" {
		t.Errorf("SSEDecode: msgs = %v, want [a b]", msgs)
	}
}

func TestSSEDecode_BOMNoSpace(t *testing.T) {
	// BOM + data:x (no space) + \n\n
	raw := []byte("\xef\xbb\xbfdata:x\n\n")
	msgs, err := vitni.SSEDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0] != "x" {
		t.Errorf("SSEDecode BOM: msgs = %v, want [x]", msgs)
	}
}

func TestSSEDecode_CRLFCommentEvent(t *testing.T) {
	// event: msg\r\n: comment\r\nid: 7\r\ndata: hello\r\ndata: world\r\n\r\n
	raw := []byte("event: msg\r\n: a comment line\r\nid: 7\r\ndata: hello\r\ndata: world\r\n\r\n")
	msgs, err := vitni.SSEDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0] != "hello\nworld" {
		t.Errorf("SSEDecode CRLF: msgs = %v, want [hello\\nworld]", msgs)
	}
}

func TestSSEDecode_EmptyDataNotDispatched(t *testing.T) {
	// event with no data lines -> empty data -> not dispatched
	raw := []byte("event: ping\n\n")
	msgs, err := vitni.SSEDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Errorf("SSEDecode empty: got %d messages, want 0", len(msgs))
	}
}

// -------------------------------------------------------------------
// Unit tests for CostCanon
// -------------------------------------------------------------------

func TestCostCanon_ValidStringInts(t *testing.T) {
	input := json.RawMessage(`{"tokens":"1500","usd_micros":"10000000000","wall_ms":"845","rail_ref":null}`)
	got, err := vitni.CostCanon(input)
	if err != nil {
		t.Fatal(err)
	}
	wantHex := "7b227261696c5f726566223a6e756c6c2c22746f6b656e73223a2231353030222c227573645f6d6963726f73223a223130303030303030303030222c2277616c6c5f6d73223a22383435227d"
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("CostCanon hex = %s, want %s", hex.EncodeToString(got), wantHex)
	}
}

func TestCostCanon_NumberError(t *testing.T) {
	input := json.RawMessage(`{"tokens":1500,"usd_micros":"10","wall_ms":"5","rail_ref":null}`)
	_, err := vitni.CostCanon(input)
	if err == nil {
		t.Fatal("expected error for numeric tokens, got nil")
	}
}

// -------------------------------------------------------------------
// Vector-driven tests (load all vectors, run against implementations)
// -------------------------------------------------------------------

func TestVectors_JCS(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Command != "jcs" {
			continue
		}
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp struct {
				Value json.RawMessage `json:"value"`
			}
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatal(err)
			}
			got, err := vitni.JCS(inp.Value)
			if err != nil {
				t.Fatal(err)
			}
			// Anchor is optional: when absent, the harness only checks
			// cross-impl agreement. Here we just assert JCS did not error.
			if len(v.Anchor) == 0 || string(v.Anchor) == "null" {
				return
			}
			var anchor struct {
				CanonicalHex string `json:"canonical_hex"`
				ByteLen      int    `json:"byte_len"`
			}
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != anchor.CanonicalHex {
				t.Errorf("canonical_hex = %s, want %s", hex.EncodeToString(got), anchor.CanonicalHex)
			}
			if len(got) != anchor.ByteLen {
				t.Errorf("byte_len = %d, want %d", len(got), anchor.ByteLen)
			}
		})
	}
}

func TestVectors_Digest(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Command != "digest" {
			continue
		}
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp struct {
				BytesB64 string `json:"bytes_b64"`
			}
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatal(err)
			}
			if isErrorVector(t, v.Anchor) {
				// Malformed-base64 rejection is a CLI-layer concern (main.go
				// decodes before the library); assert both standard decoders
				// reject it, mirroring the CLI. Cross-impl parity for these is
				// checked end-to-end by conformance/compare.mjs.
				assertBase64Rejected(t, inp.BytesB64)
				return
			}
			raw, err := base64.StdEncoding.DecodeString(inp.BytesB64)
			if err != nil {
				// Try raw (no padding)
				raw, err = base64.RawStdEncoding.DecodeString(inp.BytesB64)
				if err != nil {
					t.Fatalf("base64 decode: %v", err)
				}
			}
			got, err := vitni.Digest(raw)
			if err != nil {
				t.Fatal(err)
			}
			var anchor struct {
				Hashstr string `json:"hashstr"`
			}
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}
			if got != anchor.Hashstr {
				t.Errorf("hashstr = %q, want %q", got, anchor.Hashstr)
			}
		})
	}
}

func TestVectors_ReceiptID(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Command != "receipt-id" {
			continue
		}
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp struct {
				Receipt json.RawMessage `json:"receipt"`
			}
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatal(err)
			}
			canonHex, receiptID, err := vitni.ReceiptID(inp.Receipt)
			if err != nil {
				t.Fatalf("ReceiptID error: %v", err)
			}
			var anchor struct {
				CanonicalHex string `json:"canonical_hex"`
				ReceiptID    string `json:"receipt_id"`
			}
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}
			if canonHex != anchor.CanonicalHex {
				t.Errorf("canonical_hex = %s, want %s", canonHex, anchor.CanonicalHex)
			}
			if receiptID != anchor.ReceiptID {
				t.Errorf("receipt_id = %s, want %s", receiptID, anchor.ReceiptID)
			}
		})
	}
}

func TestVectors_SSEOutputsHash(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Command != "sse-outputs-hash" {
			continue
		}
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp struct {
				RawB64 string `json:"raw_b64"`
				Mode   string `json:"mode"`
			}
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatal(err)
			}
			if isErrorVector(t, v.Anchor) {
				// CLI-layer strict base64 rejection; see TestVectors_Digest.
				assertBase64Rejected(t, inp.RawB64)
				return
			}
			rawBytes, err := base64.StdEncoding.DecodeString(inp.RawB64)
			if err != nil {
				rawBytes, err = base64.RawStdEncoding.DecodeString(inp.RawB64)
				if err != nil {
					t.Fatalf("base64 decode: %v", err)
				}
			}
			decodedHex, outputsHash, err := vitni.SSEOutputsHash(rawBytes, inp.Mode)
			if err != nil {
				t.Fatalf("SSEOutputsHash error: %v", err)
			}
			var anchor struct {
				DecodedHex  string `json:"decoded_hex"`
				OutputsHash string `json:"outputs_hash"`
			}
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}
			if decodedHex != anchor.DecodedHex {
				t.Errorf("decoded_hex = %s, want %s", decodedHex, anchor.DecodedHex)
			}
			if outputsHash != anchor.OutputsHash {
				t.Errorf("outputs_hash = %s, want %s", outputsHash, anchor.OutputsHash)
			}
		})
	}
}

// -------------------------------------------------------------------
// Vector-driven test for sign (§10) + sign↔verify round-trip
// -------------------------------------------------------------------

func TestVectors_Sign(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Command != "sign" {
			continue
		}
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp struct {
				Receipt       json.RawMessage `json:"receipt"`
				Kid           string          `json:"kid"`
				PrivateKeyB64 string          `json:"private_key_b64"`
			}
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatal(err)
			}

			// Decode the 32-byte seed (standard or raw base64), expand to a key.
			seed, err := base64.StdEncoding.DecodeString(inp.PrivateKeyB64)
			if err != nil {
				seed, err = base64.RawStdEncoding.DecodeString(inp.PrivateKeyB64)
				if err != nil {
					t.Fatalf("base64 decode seed: %v", err)
				}
			}
			if len(seed) != ed25519.SeedSize {
				t.Fatalf("seed len = %d, want %d", len(seed), ed25519.SeedSize)
			}
			priv := ed25519.NewKeyFromSeed(seed)

			var receipt vitni.Receipt
			if err := json.Unmarshal(inp.Receipt, &receipt); err != nil {
				t.Fatal(err)
			}
			signed, err := vitni.Sign(receipt, inp.Kid, priv)
			if err != nil {
				t.Fatalf("Sign error: %v", err)
			}

			var anchor struct {
				SignedReceipt string `json:"signed_receipt"`
			}
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}
			if signed != anchor.SignedReceipt {
				t.Errorf("signed_receipt mismatch:\n got:  %s\n want: %s", signed, anchor.SignedReceipt)
			}

			// Round-trip strengthener: the produced JWS must verify under the
			// public key derived from the same seed. Proves sign↔verify interop.
			pub := priv.Public().(ed25519.PublicKey)
			x := base64.RawURLEncoding.EncodeToString(pub)
			valid, reason := vitni.Verify(vitni.VerifyInput{
				SignedReceipt: signed,
				Keys: map[string]map[string]vitni.RegistryKey{
					receipt.PerformerID: {
						inp.Kid: {Kty: "OKP", Crv: "Ed25519", X: x, Alg: "EdDSA", Status: "active"},
					},
				},
			})
			if !valid || reason != "ok" {
				t.Errorf("round-trip verify = (%v, %q), want (true, \"ok\")", valid, reason)
			}
		})
	}
}

func TestSign_Errors(t *testing.T) {
	goodSeed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	r := vitni.Receipt{
		Binding:     "mcp",
		PerformerID: "srv-ed",
		Method:      "mcp:echo",
		InputsHash:  "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
		OutputsHash: "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
		Cost:        vitni.Cost{Tokens: "10", USDMicros: "0", WallMs: "3"},
		Status:      "OK",
		LogPolicy:   "best_effort",
		Ts:          "2026-05-28T00:00:00Z",
		Nonce:       "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",
	}

	// empty kid → error
	if _, err := vitni.Sign(r, "", goodSeed); err == nil {
		t.Error("Sign with empty kid: expected error, got nil")
	}
	// wrong-size key → error
	if _, err := vitni.Sign(r, "ed-1", ed25519.PrivateKey(make([]byte, 16))); err == nil {
		t.Error("Sign with short key: expected error, got nil")
	}
}

func TestVectors_CostCanon(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Command != "cost-canon" {
			continue
		}
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp struct {
				Cost json.RawMessage `json:"cost"`
			}
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatal(err)
			}

			var anchor map[string]json.RawMessage
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}

			if _, hasErr := anchor["error"]; hasErr {
				// Expect error
				_, err := vitni.CostCanon(inp.Cost)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				got, err := vitni.CostCanon(inp.Cost)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				var expectedAnchor struct {
					CanonicalHex string `json:"canonical_hex"`
				}
				if err := json.Unmarshal(v.Anchor, &expectedAnchor); err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(got) != expectedAnchor.CanonicalHex {
					t.Errorf("canonical_hex = %s, want %s", hex.EncodeToString(got), expectedAnchor.CanonicalHex)
				}
			}
		})
	}
}

func TestExtField(t *testing.T) {
	base := vitni.Receipt{
		V: "vitni/0.2", Binding: "local", PerformerID: "daimon:kibukx",
		Method: "local:daimon.serialize",
		InputsHash:  "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
		OutputsHash: "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
		Cost:      vitni.Cost{Tokens: "10", USDMicros: "0", WallMs: "3"},
		Status:    "OK", LogPolicy: "best_effort",
		Ts: "2026-05-28T00:00:00Z", Nonce: "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",
	}

	// nil Ext must serialize WITHOUT an "ext" key ("| absent" in the spec)
	noExt, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(noExt, []byte(`"ext"`)) {
		t.Errorf("nil Ext must be absent from JSON, got %s", noExt)
	}

	// set Ext must serialize as a JSON object under "ext"
	withExt := base
	withExt.Ext = map[string]any{"dev.daimon/prompt_version": "3"}
	got, err := json.Marshal(withExt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"ext":{"dev.daimon/prompt_version":"3"}`)) {
		t.Errorf("Ext not serialized, got %s", got)
	}
}
