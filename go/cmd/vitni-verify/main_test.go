package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	vitni "github.com/Daily-Nerd/vitni/go"
	"github.com/Daily-Nerd/vitni/go/internal/fields"
)

// runOn feeds stdin through the same single decode the gate in respond does,
// then runs one command, for tests that exercise a runner without the gate.
func runOn(r runner, stdin string) (json.RawMessage, error) {
	in, err := fields.Object([]byte(stdin))
	if err != nil {
		return nil, err
	}
	return r(in, []byte(stdin))
}

// The run* functions are the CLI dispatch layer. End-to-end they are exercised
// by conformance/compare.mjs (a subprocess), which `go test -coverprofile`
// cannot observe — so they read as 0% and the negative vectors' library error
// paths go uncounted. This test replays every conformance vector through the
// matching run* function in-process, covering the dispatch AND the library
// branches (malformed base64, non-canonical payloads, spliced chains, …) that
// the negative vectors drive.

// vec is one conformance vector file. A vector pins its stdin in exactly one of
// three forms; the raw forms are pointers so that a present-but-empty value is
// EMPTY stdin, not "absent" (a plain string cannot tell the two apart).
type vec struct {
	Name        string          `json:"name"`
	Command     string          `json:"command"`
	Input       json.RawMessage `json:"input"`
	InputRaw    *string         `json:"input_raw"`
	InputRawB64 *string         `json:"input_raw_b64"`
	Anchor      json.RawMessage `json:"anchor"`
}

// vecStdin returns the exact stdin bytes a vector pins: input_raw verbatim,
// input_raw_b64 base64-decoded (bytes a JSON string cannot carry, such as
// invalid UTF-8), or the serialized input object. Exactly one form is allowed.
func vecStdin(v vec) ([]byte, error) {
	forms := 0
	if v.Input != nil {
		forms++
	}
	if v.InputRaw != nil {
		forms++
	}
	if v.InputRawB64 != nil {
		forms++
	}
	if forms != 1 {
		return nil, fmt.Errorf("%s: exactly one of input, input_raw, input_raw_b64 required, found %d", v.Name, forms)
	}
	switch {
	case v.InputRawB64 != nil:
		return base64.StdEncoding.DecodeString(*v.InputRawB64)
	case v.InputRaw != nil:
		return []byte(*v.InputRaw), nil
	default:
		return []byte(v.Input), nil
	}
}

func TestVecStdin(t *testing.T) {
	s := func(x string) *string { return &x }
	cases := []struct {
		name    string
		v       vec
		want    []byte
		wantErr bool
	}{
		{"input", vec{Input: json.RawMessage(`{"a":1}`)}, []byte(`{"a":1}`), false},
		{"raw", vec{InputRaw: s(`{"a":1,"a":2}`)}, []byte(`{"a":1,"a":2}`), false},
		{"raw-empty-is-empty-stdin", vec{InputRaw: s("")}, []byte{}, false},
		{"b64-empty-is-empty-stdin", vec{InputRawB64: s("")}, []byte{}, false},
		{"b64-invalid-utf8", vec{InputRawB64: s("/w==")}, []byte{0xff}, false},
		{"b64-bom", vec{InputRawB64: s("77u/e30=")}, []byte("\xef\xbb\xbf{}"), false},
		{"none", vec{}, nil, true},
		{"two-forms", vec{InputRaw: s("x"), InputRawB64: s("")}, nil, true},
		{"input-and-raw", vec{Input: json.RawMessage(`{}`), InputRaw: s("")}, nil, true},
		{"bad-b64", vec{InputRawB64: s("!!!")}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := vecStdin(c.v)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err == nil && (got == nil || !bytes.Equal(got, c.want)) {
				t.Errorf("stdin = %#v, want %#v", got, c.want)
			}
		})
	}
}

// TestRespond_AllVectors replays every conformance vector through respond, the
// whole CLI pipeline after argv and stdin reading (command lookup, the stdin
// gate, the command, JCS output), with the exact stdin bytes the vector pins.
// End-to-end the CLI is exercised by conformance/compare.mjs (a subprocess),
// which `go test -coverprofile` cannot observe; this covers the same ground
// in-process and compares the printed line with the anchor.
func TestRespond_AllVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "conformance", "vectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read vectors dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" || strings.HasPrefix(e.Name(), "_") {
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
		t.Run(v.Name, func(t *testing.T) {
			stdin, err := vecStdin(v)
			if err != nil {
				t.Fatal(err)
			}
			line := respond(v.Command, stdin)
			if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
				t.Fatalf("output is not exactly one line: %q", line)
			}
			var got map[string]any
			if err := json.Unmarshal(line, &got); err != nil {
				t.Fatalf("output is not a JSON object: %q", line)
			}
			if len(v.Anchor) == 0 {
				// Unanchored vectors only probe cross-impl agreement here.
				if _, isErr := got["error"]; isErr {
					t.Fatalf("unanchored vector errored: %s", line)
				}
				return
			}
			var want map[string]any
			if err := json.Unmarshal(v.Anchor, &want); err != nil {
				t.Fatalf("anchor: %v", err)
			}
			for k, w := range want {
				if !reflect.DeepEqual(got[k], w) {
					t.Errorf("%s: got %v, want %v (line %s)", k, got[k], w, line)
				}
			}
		})
	}
}

// TestRespond_ResolvesCommandBeforeParsing pins D8: an unknown command is
// unsupported_command whatever the stdin is, and a missing command's stdin is
// never looked at.
func TestRespond_ResolvesCommandBeforeParsing(t *testing.T) {
	for _, stdin := range []string{")(", "", "[]", "{\"a\":1e400}"} {
		if got := string(respond("not-a-command", []byte(stdin))); got != "{\"error\":\"unsupported_command\"}\n" {
			t.Errorf("stdin %q: got %q", stdin, got)
		}
	}
}

// TestRespond_StdinDepth pins the depth limit at the stdin edge (no host limit
// is relied on): the top-level object is depth 1, so {"value": <127 arrays>}
// is exactly 128 and one more array is 129.
func TestRespond_StdinDepth(t *testing.T) {
	nest := func(n int) []byte {
		return []byte(`{"value":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`)
	}
	if got := string(respond("jcs", nest(127))); strings.Contains(got, "error") {
		t.Errorf("depth 128 must be accepted, got %s", got)
	}
	if got := string(respond("jcs", nest(128))); got != "{\"error\":\"invalid_input\"}\n" {
		t.Errorf("depth 129 must be invalid_input, got %s", got)
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
			if _, err := runOn(runSign, stdin); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
	// unknown-command is handled in main(); assert the error string carries the
	// field name so the message is actionable.
	if _, err := runOn(runSign, `{"receipt":{`+base+`,"FOO":"x"},`+key+`}`); err == nil || !strings.Contains(err.Error(), "FOO") {
		t.Errorf("unknown-key error should name the field, got %v", err)
	}
}

// TestRespond_NeverInternalError is R0.12: no stdin reaches jcs_output_error (or
// any code outside the contract's vocabulary). For every command and every way
// the stdin itself can be wrong, the answer is exactly one JSON object on one
// line. A command bug that fails on input shows up as a code that is not an
// input verdict.
func TestRespond_NeverInternalError(t *testing.T) {
	baselines := map[string]string{
		"jcs":               `{"value":{"b":1,"a":2}}`,
		"hashstring":        `{"algo":"sha2-256","digest_hex":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}`,
		"digest":            `{"bytes_b64":"aGVsbG8="}`,
		"receipt-id":        `{"receipt":{"v":"vitni/0.2","binding":"mcp"}}`,
		"sse-outputs-hash":  `{"mode":"sse","raw_b64":"ZGF0YTogaGVsbG8KCg=="}`,
		"cost-canon":        `{"cost":{"tokens":"1","usd_micros":"0","wall_ms":"0","rail_ref":null}}`,
		"verify":            `{"signed_receipt":"a.b.c","keys":{},"policy":null}`,
		"verify-chain":      `{"receipts":[],"keys":{},"policy":null}`,
		"a2a-artifact-hash": `{"artifact":{"parts":[{"kind":"text","text":"hi"}]}}`,
		"sign":              `{"receipt":{"v":"vitni/0.2"},"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}`,
		"keygen":            `{}`,
	}
	for command := range commands {
		if _, ok := baselines[command]; !ok {
			t.Fatalf("the property test has no baseline for command %q", command)
		}
	}
	withMember := func(base string, member []byte) []byte {
		out := []byte(base[:len(base)-1] + `,"zz":`)
		out = append(out, member...)
		return append(out, '}')
	}
	mutations := map[string]func(string) []byte{
		"baseline":                  func(b string) []byte { return []byte(b) },
		"bom":                       func(b string) []byte { return append([]byte{0xef, 0xbb, 0xbf}, b...) },
		"invalid utf-8":             func(b string) []byte { return withMember(b, []byte("\"\xff\"")) },
		"lone surrogate escape":     func(b string) []byte { return withMember(b, []byte(`"\ud800"`)) },
		"lone low surrogate escape": func(b string) []byte { return withMember(b, []byte(`"\udc00"`)) },
		"non-finite number":         func(b string) []byte { return withMember(b, []byte(`1e400`)) },
		"array":                     func(string) []byte { return []byte(`[]`) },
		"null":                      func(string) []byte { return []byte(`null`) },
		"string":                    func(string) []byte { return []byte(`"x"`) },
		"empty":                     func(string) []byte { return []byte{} },
		"trailing garbage":          func(b string) []byte { return []byte(b + " x") },
		"nul suffix":                func(b string) []byte { return append([]byte(b), 0) },
		"depth 129":                 func(b string) []byte { return withMember(b, []byte(strings.Repeat("[", 128)+strings.Repeat("]", 128))) },
		"depth 100000": func(b string) []byte {
			return withMember(b, []byte(strings.Repeat("[", 100000)+strings.Repeat("]", 100000)))
		},
	}
	for command, base := range baselines {
		for label, mutate := range mutations {
			t.Run(command+"/"+label, func(t *testing.T) {
				line := respond(command, mutate(base))
				if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
					t.Fatalf("output is not exactly one line: %q", line)
				}
				var got map[string]any
				if err := json.Unmarshal(line, &got); err != nil {
					t.Fatalf("output is not a JSON object: %q", line)
				}
				if code, _ := got["error"].(string); code == "jcs_output_error" || code == "internal_error" || code == "stdin_read_error" || code == "missing_command" {
					t.Fatalf("stdin reached %s: %s", code, line)
				}
			})
		}
	}
}
