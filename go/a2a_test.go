package vitni_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Daily-Nerd/vitni/go"
)

// TestVectors_A2AArtifactHash drives the a2a-artifact-hash command against every a2a-*.json vector.
func TestVectors_A2AArtifactHash(t *testing.T) {
	count := 0
	for _, v := range loadVectors(t) {
		if v.Command != "a2a-artifact-hash" {
			continue
		}
		count++
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var inp struct {
				Artifact json.RawMessage `json:"artifact"`
			}
			if err := json.Unmarshal(v.Input, &inp); err != nil {
				t.Fatalf("unmarshal input: %v", err)
			}

			var anchor map[string]json.RawMessage
			if err := json.Unmarshal(v.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}

			descriptorBytes, outputsHash, err := vitni.A2AArtifactHash(inp.Artifact)

			if _, wantErr := anchor["error"]; wantErr {
				if err == nil {
					t.Fatalf("expected error, got descriptor=%s hash=%s", descriptorBytes, outputsHash)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var expected struct {
				OutputsHash   string `json:"outputs_hash"`
				DescriptorHex string `json:"descriptor_hex"`
			}
			if err := json.Unmarshal(v.Anchor, &expected); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(descriptorBytes) != expected.DescriptorHex {
				t.Errorf("descriptor_hex = %s, want %s", hex.EncodeToString(descriptorBytes), expected.DescriptorHex)
			}
			if outputsHash != expected.OutputsHash {
				t.Errorf("outputs_hash = %q, want %q", outputsHash, expected.OutputsHash)
			}
		})
	}
	if count == 0 {
		t.Fatal("no a2a-artifact-hash vectors found")
	}
}

// TestA2A_UnsupportedNoBytesNoUri checks the unsupported_part error.
func TestA2A_UnsupportedNoBytesNoUri(t *testing.T) {
	artifact := json.RawMessage(`{"parts":[{"kind":"file","file":{"mimeType":"x/y"}}]}`)
	_, _, err := vitni.A2AArtifactHash(artifact)
	if err == nil {
		t.Fatal("expected error for file part with neither bytes nor uri")
	}
}

// TestA2A_UnknownKind checks unknown kind → error.
func TestA2A_UnknownKind(t *testing.T) {
	artifact := json.RawMessage(`{"parts":[{"kind":"video","src":"x"}]}`)
	_, _, err := vitni.A2AArtifactHash(artifact)
	if err == nil {
		t.Fatal("expected error for unknown kind")
	}
}
