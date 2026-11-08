---
id: 0
type: landmine
title: a truthiness check on a vector's input_raw treats the empty string as absent and runs the wrong stdin
severity: medium
confidence: 0.85
created: 2026-11-07
authors: ["claude-code"]
anchors:
  - path: go/cmd/vitni-verify/main_test.go
  - path: go/vitni_test.go
  - pattern: "InputRaw\\s*!=\\s*\"\""
evidence:
  - note: "py-reference-verifier 0b: main_test.go chose stdin with `if v.InputRaw != \"\"`, so an empty-stdin vector fell through to v.Input (nil) and only passed by coincidence"
expires:
  condition: "the Go vector runners decode every vector through one shared helper that is unit-tested for the empty case"
  review_after: 2027-05-01
status: candidate
---

The Go CLI vector test selected the stdin form with `v.InputRaw != ""`. An
empty `input_raw` (or `input_raw_b64`) is a deliberate vector meaning "empty
stdin", but a plain string field cannot distinguish "empty" from "absent", so
the runner used the structured `input` instead (nil). The vector passed for
the wrong reason, and a future vector with an empty-stdin expectation that
differs from the nil-input outcome would have been wrong silently.

Fix pattern: make the raw fields `*string` (present means non-nil) and route
every vector through one tested helper (`vecStdin`) that also enforces
exactly one stdin form. The Node side must use `!== undefined`, never
truthiness, for the same reason.
