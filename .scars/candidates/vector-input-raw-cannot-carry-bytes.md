---
id: 0
type: landmine
title: vector input_raw is a JSON string so it cannot carry invalid UTF-8 or a raw lone surrogate, use input_raw_b64
severity: medium
confidence: 0.9
created: 2026-11-07
authors: ["claude-code"]
anchors:
  - path: conformance/vectors/
  - path: conformance/compare.mjs
  - pattern: "input_raw"
evidence:
  - note: "py-reference-verifier 0b: neg-jcs-invalid-utf8 needs the stdin bytes 7b 22 76 ... ff ... and no JSON string value can hold a lone 0xff byte; compare.mjs used spawnSync encoding utf8, which also rewrote an impl's raw 0xff output to U+FFFD and hid it"
expires:
  condition: "vectors stop carrying stdin as JSON text, or input_raw_b64 is removed in favor of a binary side file"
  review_after: 2027-05-01
status: candidate
---

A vector file is JSON, so `input_raw` is a Unicode string: it can hold the
ASCII escape text `\ud800` (six characters) but never a raw invalid UTF-8
byte, a BOM-then-garbage prefix, or a lone surrogate code unit. A vector that
needs those bytes silently tests something else if it is forced through
`input_raw`.

Use `input_raw_b64` (standard base64 of the exact stdin bytes). The harness,
the Go CLI test and the TS test all decode it to bytes and pipe them
unmodified. A present-but-empty value is empty stdin, never "absent".

The same trap exists on the output side: reading a child's stdout as `utf8`
replaces invalid bytes with U+FFFD before any comparison, so an impl that
echoes a raw `ff` looks like one that emits `efbfbd`. Compare stdout as
Buffers and decode strictly (`NON-UTF8-OUTPUT` fails the vector).
