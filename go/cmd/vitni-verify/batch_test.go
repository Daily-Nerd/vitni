package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// batchOf renders {"questions":[...]} from raw JSON elements.
func batchOf(elements ...string) []byte {
	return []byte(`{"questions":[` + strings.Join(elements, ",") + `]}`)
}

// resultsOf splits a verify-batch output line into its raw result elements.
func resultsOf(t *testing.T, line []byte) []string {
	t.Helper()
	var out struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(line, &out); err != nil || out.Results == nil {
		t.Fatalf("not a results object: %q (%v)", line, err)
	}
	got := make([]string, len(out.Results))
	for i, r := range out.Results {
		got[i] = string(r)
	}
	return got
}

// TestVerifyBatch_ElementsAreIsolated pins the per-element contract: result i
// answers question i alone, in order, and a bad element never changes another.
func TestVerifyBatch_ElementsAreIsolated(t *testing.T) {
	line := respond("verify-batch", batchOf(
		`{}`,                                   // verdict: malformed
		`5`,                                    // not an object
		`null`,                                 // not an object
		`[]`,                                   // not an object
		`{"signed_receipt":5}`,                 // wrong member type
		`{"keys":[]}`,                          // wrong member type
		`{"signed_receipt":"a.b.c","keys":{}}`, // verdict: malformed
	))
	want := []string{
		`{"reason":"malformed","valid":false}`,
		`{"error":"invalid_input"}`,
		`{"error":"invalid_input"}`,
		`{"error":"invalid_input"}`,
		`{"error":"invalid_input"}`,
		`{"error":"invalid_input"}`,
		`{"reason":"malformed","valid":false}`,
	}
	got := resultsOf(t, line)
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d: %s", len(got), len(want), line)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result %d: got %s, want %s", i, got[i], want[i])
		}
	}
	if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
		t.Errorf("output is not exactly one line: %q", line)
	}
}

func TestVerifyBatch_EmptyList(t *testing.T) {
	if got := string(respond("verify-batch", batchOf())); got != "{\"results\":[]}\n" {
		t.Errorf("got %q", got)
	}
}

// TestVerifyBatch_TopLevelShape: the batch itself must be {"questions":[...]}.
func TestVerifyBatch_TopLevelShape(t *testing.T) {
	for _, stdin := range []string{
		`{}`, `{"questions":null}`, `{"questions":{}}`, `{"questions":"x"}`, `{"questions":5}`,
		`{"Questions":[]}`, `[]`, `null`, ``,
	} {
		if got := string(respond("verify-batch", []byte(stdin))); got != "{\"error\":\"invalid_input\"}\n" {
			t.Errorf("stdin %q: got %q", stdin, got)
		}
	}
}

// TestVerifyBatch_Limit pins the boundary: maxBatchQuestions answers, one more
// is batch_too_large (the caller must split it, which is not an input fix).
func TestVerifyBatch_Limit(t *testing.T) {
	if maxBatchQuestions != 65536 {
		t.Fatalf("maxBatchQuestions = %d, the contract says 65536", maxBatchQuestions)
	}
	build := func(n int) []byte {
		return []byte(`{"questions":[` + strings.TrimSuffix(strings.Repeat(`{},`, n), ",") + `]}`)
	}
	if got := resultsOf(t, respond("verify-batch", build(maxBatchQuestions))); len(got) != maxBatchQuestions {
		t.Errorf("MAX questions: got %d results", len(got))
	}
	if got := string(respond("verify-batch", build(maxBatchQuestions+1))); got != "{\"error\":\"batch_too_large\"}\n" {
		t.Errorf("MAX+1 questions: got %q", got)
	}
}

// TestVerifyBatch_TextFaultsAreBatchWide: a fault detected on the raw text, not
// on a parsed element, fails the whole batch, even when the other elements are fine.
func TestVerifyBatch_TextFaultsAreBatchWide(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	cases := map[string][]byte{
		"lone surrogate": batchOf(`{}`, `{"x":"\ud800"}`),
		"non-finite":     batchOf(`{}`, `{"x":1e400}`),
		// the elements sit two levels deeper than a lone verify input: depth 3 + n
		"depth 129": batchOf(`{}`, `{"x":`+deep(126)+`}`),
	}
	for name, stdin := range cases {
		if got := string(respond("verify-batch", stdin)); got != "{\"error\":\"invalid_input\"}\n" {
			t.Errorf("%s: got %q", name, got)
		}
	}
	// 3 + 125 = 128 is the last accepted depth, and a lone verify accepts two more.
	if got := string(respond("verify-batch", batchOf(`{"x":`+deep(125)+`}`))); strings.Contains(got, "error") {
		t.Errorf("depth 128 must be accepted, got %s", got)
	}
	if got := string(respond("verify", []byte(`{"x":`+deep(127)+`}`))); strings.Contains(got, "error") {
		t.Errorf("a lone verify at depth 128 must be accepted, got %s", got)
	}
}

// TestVerifyBatch_DuplicateKeysAreLastWins: verify's policy, not the
// reject-duplicates policy of the commands whose value flows into JCS.
func TestVerifyBatch_DuplicateKeysAreLastWins(t *testing.T) {
	line := respond("verify-batch", []byte(`{"questions":[],"questions":[{"signed_receipt":5,"signed_receipt":null}]}`))
	got := resultsOf(t, line)
	if len(got) != 1 || got[0] != `{"reason":"malformed","valid":false}` {
		t.Errorf("got %s", line)
	}
}

// TestVerifyBatch_MatchesVerifyOnEveryVector is the drift guard for the shared
// code path: every structured verify vector, wrapped as a one-element batch,
// must give results[0] byte-identical to what verify prints for it alone.
func TestVerifyBatch_MatchesVerifyOnEveryVector(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "conformance", "vectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var v vec
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
		if v.Command != "verify" || v.Input == nil {
			continue
		}
		alone := strings.TrimSuffix(string(respond("verify", []byte(v.Input))), "\n")
		got := resultsOf(t, respond("verify-batch", batchOf(string(v.Input))))
		if len(got) != 1 || got[0] != alone {
			t.Errorf("%s: batch %v, alone %s", v.Name, got, alone)
		}
		checked++
	}
	if checked < 100 {
		t.Fatalf("only %d verify vectors checked; the scan is vacuous", checked)
	}
}
