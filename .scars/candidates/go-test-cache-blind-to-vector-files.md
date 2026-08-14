---
id: 0
type: landmine
title: go test cache does not invalidate on conformance-vector file changes — cached green lies after adding vectors
severity: high
confidence: 0.9
created: 2026-08-04
authors: ["claude-code"]
anchors:
  - path: go/vitni_test.go
  - path: conformance/vectors/
  - pattern: "go test \\./\\.\\.\\."
evidence:
  - pr: 60
  - note: "CI run 30894502466: TestVectors_SSEOutputsHash failed on a vector the implementer's local `go test ./...` had reported green — every local run after adding the vector was serving `(cached)` results"
expires:
  condition: "vector-driven Go tests embed vectors via go:embed or the test harness hashes the vectors dir into the cache key"
  review_after: 2027-02-01
status: candidate
---

The Go vector-driven tests (`TestVectors_*` in `go/vitni_test.go`) load
`conformance/vectors/*.json` at runtime via `os.ReadDir`/`os.ReadFile`. The
go test cache keys on source files and declared inputs — it does NOT track
files opened at runtime. Consequence: after adding or regenerating vectors,
`go test ./...` can print `ok ... (cached)` from a run that never saw the
new vectors. In PR #60 this produced a confidently reported green gate that
CI immediately contradicted (TestVectors_SSEOutputsHash failed on the new
`neg-sse-nonfinite-result` vector).

What a future editor must do instead: after ANY change under
`conformance/vectors/`, run Go tests with the cache bypassed —
`go test -count=1 ./...` — or treat a `(cached)` marker in the output as an
invalid result for gating. The cross-impl harness
(`node conformance/compare.mjs`) is immune (no cache), so a harness-green +
go-test-green disagreement is itself the symptom: suspect the cache first.
