package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vitni "github.com/Daily-Nerd/vitni/go"
)

// The run* functions are the CLI dispatch layer. End-to-end they are exercised
// by conformance/compare.mjs (a subprocess), which `go test -coverprofile`
// cannot observe — so they read as 0% and the negative vectors' library error
// paths go uncounted. This test replays every conformance vector through the
// matching run* function in-process, covering the dispatch AND the library
// branches (malformed base64, non-canonical payloads, spliced chains, …) that
// the negative vectors drive.

var dispatch = map[string]func([]byte) (json.RawMessage, error){
	"jcs":               runJCS,
	"hashstring":        runHashString,
	"digest":            runDigest,
	"receipt-id":        runReceiptID,
	"sse-outputs-hash":  runSSEOutputsHash,
	"cost-canon":        runCostCanon,
	"verify":            runVerify,
	"verify-chain":      runVerifyChain,
	"a2a-artifact-hash": runA2AArtifactHash,
	"sign":              runSign,
}

type vec struct {
	Name     string          `json:"name"`
	Command  string          `json:"command"`
	Input    json.RawMessage `json:"input"`
	InputRaw string          `json:"input_raw"`
	Anchor   json.RawMessage `json:"anchor"`
}

func TestDispatch_AllVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "conformance", "vectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read vectors dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var v vec
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		fn, ok := dispatch[v.Command]
		if !ok {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			// Exact stdin bytes: input_raw verbatim (duplicate keys) or the
			// serialized input object.
			var stdin []byte
			if v.InputRaw != "" {
				stdin = []byte(v.InputRaw)
			} else {
				stdin = v.Input
			}
			out, cmdErr := fn(stdin)

			// A vector whose anchor asserts an error (or that uses input_raw
			// for a duplicate-key rejection) must produce a non-nil error whose
			// mapped code matches; a happy vector must not error.
			var anchor map[string]json.RawMessage
			_ = json.Unmarshal(v.Anchor, &anchor)
			_, wantErr := anchor["error"]
			// verify / verify-chain never error at the CLI layer — an invalid
			// receipt is a {valid:false} result, not a Go error — so only the
			// command-error vectors (invalid_input etc.) are error cases.
			if wantErr && v.Command != "verify" && v.Command != "verify-chain" {
				if cmdErr == nil {
					t.Fatalf("expected error, got output %s", out)
				}
				var wantCode string
				_ = json.Unmarshal(anchor["error"], &wantCode)
				if got := errorCode(cmdErr); got != wantCode {
					t.Errorf("error code = %q, want %q", got, wantCode)
				}
				return
			}
			if cmdErr != nil {
				t.Fatalf("unexpected error: %v", cmdErr)
			}
			if len(out) == 0 {
				t.Errorf("empty output")
			}
		})
	}
}

// TestErrorCode covers the sentinel-to-string mapping used by writeError.
func TestErrorCode(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{vitni.ErrReceiptIDMustBeAbsent, "receipt_id_must_be_absent"},
		{vitni.ErrUnsupportedPart, "unsupported_part"},
		{errInvalidPrivateKey, "invalid_private_key"},
		{errKidRequired, "kid_required"},
		{errors.New("something else entirely"), "invalid_input"},
	}
	for _, c := range cases {
		if got := errorCode(c.err); got != c.want {
			t.Errorf("errorCode(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// TestRunSign_ContractErrors covers the sign-time validation branches directly
// (unknown key, non-string cost, absent receipt, receipt_id present).
func TestRunSign_ContractErrors(t *testing.T) {
	key := `"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="`
	base := `"v":"vitni/0.2","binding":"mcp","action_ref":null,"performer_id":"srv","requester_id":null,"method":"mcp:x","inputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","outputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","cost":{"tokens":"10","usd_micros":"0","wall_ms":"3","rail_ref":null},"status":"OK","reason":null,"parent_receipt_hash":null,"log_policy":"best_effort","ts":"2026-05-28T00:00:00Z","nonce":"uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ"`
	cases := []struct{ name, receipt string }{
		{"unknown-key", `{` + base + `,"FOO":"x"}`},
		{"receipt-id-present", `{` + base + `,"receipt_id":"u123"}`},
		{"missing-receipt", ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdin string
			if c.receipt == "" {
				stdin = `{` + key + `}`
			} else {
				stdin = `{"receipt":` + c.receipt + `,` + key + `}`
			}
			if _, err := runSign([]byte(stdin)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
	// unknown-command is handled in main(); assert the error string carries the
	// field name so the message is actionable.
	if _, err := runSign([]byte(`{"receipt":{` + base + `,"FOO":"x"},` + key + `}`)); err == nil || !strings.Contains(err.Error(), "FOO") {
		t.Errorf("unknown-key error should name the field, got %v", err)
	}
}
