# vitni conformance suite

**The interoperability bar for vitni implementations.** 92 language-agnostic
vectors that pin every byte the protocol commits to. Any implementation that
passes them is interoperable with every other implementation that passes them
— that is the claim this directory exists to make falsifiable.

The two reference implementations (`go/`, `ts/`) share no code and are held
**byte-identical** against this suite in CI on every commit. Agreement across
two independent runtimes is the proof of the spec's normative guarantee
([DESIGN.md §12](../docs/DESIGN.md)): *two conformant verifiers MUST produce
byte-identical verdicts and identical recomputed hashes on every vector.*

## Layout

| Path | What it is |
|------|-----------|
| [`CONTRACT.md`](CONTRACT.md) | The verifier CLI contract every implementation under test speaks — 9 commands, stdin JSON → one line of JCS-canonical JSON |
| [`vectors/`](vectors/) | The vectors, one JSON file each; `_gen*.py` are the deterministic generators |
| [`compare.mjs`](compare.mjs) | The harness — runs every vector through two implementations, asserts byte equality + anchor match |

## What the vectors cover

Positive classes prove the happy path is deterministic; negative classes
prove the dangerous paths are **closed the same way** in every implementation
— a verifier that silently accepts what another rejects is an
interoperability break, even when both are "reasonable."

| Class | Vectors | Pins |
|-------|---------|------|
| JCS canonicalization | `jcs-*`, `neg-dup-jcs*` | RFC 8785 octets, ECMAScript number serialization, duplicate-key rejection, the 2^53 boundary; ES number formatting (float-integral, -0, exponent boundaries 1e16/1e21/1e-5..1e-7, over-safe-int via input_raw), non-finite rejection, UTF-16 code-unit key sort (non-BMP) |
| Hash-string encoding | `digest-*`, `neg-hashstring-*`, `neg-digest-*` | multihash + the one pinned multibase (`u` + base64url-nopad); strict-canonical base64 accept set (newlines, excess padding, non-zero trailing bits all rejected) |
| Receipt-id derivation | `receipt-id-*`, `neg-dup-receipt-id` | `receipt_id = "u" + base64url(multihash(JCS(Receipt)))`, `receipt_id`-must-be-absent |
| Streaming (SSE) | `sse-*`, `neg-sse-*` | decode-then-hash (§4.3): CRLF/CR/LF framing, BOM strip, comment lines, split `data:` lines, JSON-RPC inner-`result` extraction, re-framed streams hashing identically |
| Cost encoding | `cost-*`, `neg-cost-*` | string-encoded integer magnitudes; JSON-number cost rejected (the silent-rounding defense) |
| Signing | `sign-*`, `neg-sign-*` | Ed25519 over JCS payload octets; seed accept set; unknown-key error channel |
| Verification + JOSE hardening | `verify-*` | valid Ed25519/ES256 accepts **and** the closed attack paths: `alg:none`, algorithm substitution, `jwk`/`jku`/`x5*` header key-injection, non-canonical payload, unknown `kid`, revoked key, wrong key, context mismatch |
| Chain / lineage | `chain-*` | 2- and 3-hop valid paths; dangling parent, link mismatch, mid-chain null parent, foreign-parent splice via `parent_performer_id` (present/null/empty-string all distinguished) |
| A2A artifact hashing | `a2a-*`, `neg-a2a-*` | the §14 descriptor canonicalization per `Part` kind; by-URI parts never dereferenced; unsupported parts rejected |
| Key generation | `keygen-*` | RFC 8032 deterministic derivation (TEST 1 anchor); present-but-empty seed rejected; malformed-seed accept set |
| CLI dispatch | `neg-cli-*` | unsupported-command and unparseable-stdin codes |

## Running the harness

Build both reference implementations, then:

```sh
cd go && go build -o ../bin/vitni-verify-go ./cmd/vitni-verify && cd ..
cd ts && npm install && npm run build && cd ..
node conformance/compare.mjs
```

Per vector the harness prints `PASS`, `DIVERGE` (implementations disagree —
both outputs shown), `ANCHOR` (they agree with each other but not with the
known-correct value), or `NOANCHOR` (an error output with no anchor asserting
the expected code). Exit is non-zero unless every vector passes.

## Testing your own implementation

The suite is the contract — not the reference code. To test a third
implementation:

1. Implement the CLI contract in [`CONTRACT.md`](CONTRACT.md): each command
   reads one JSON object on stdin and emits exactly one line of
   JCS-canonical JSON on stdout, exit 0 (errors go on stdout as
   `{"error":"<code>"}`, also exit 0).
2. Point the harness at your binary via the env vars it already honors:

```sh
# your implementation vs the Go reference
GO_VERIFY="./bin/vitni-verify-go" TS_VERIFY="your-verify-cmd" node conformance/compare.mjs
```

Byte-identical output against a reference implementation on all 92 vectors
is the conformance claim. Divergence is a finding: either your
implementation has a bug, or the spec leaked ambiguity — [file an
issue](https://github.com/Daily-Nerd/vitni/issues) for either; the second
kind is the more valuable report.

## Anchor semantics

A vector's optional `anchor` is an **externally-known-correct** expected
output — an RFC 8785 test value, an RFC 8032 test vector, a hand-computed
digest. When present, the harness asserts both implementations match the
anchor *and* each other; when absent, it asserts only cross-implementation
agreement (which catches ambiguity, but not both-wrong-the-same-way — that
is exactly what anchors exist for). Error outputs **must** be anchored:
"both implementations errored identically" is otherwise indistinguishable
from a shared bug.

## Vector file format

```json
{
  "name": "jcs/sorted-keys",
  "command": "jcs",
  "input": { "value": { "b": 1, "a": 2 } },
  "anchor": { "canonical_hex": "7b2261223a322c2262223a317d", "byte_len": 13 }
}
```

A vector may instead carry `input_raw` — the exact stdin bytes, verbatim —
for cases a parse→serialize round-trip would destroy (e.g. duplicate JSON
keys). Vectors are regenerated with `uv run` only; the generators are
deterministic (RFC 6979 for ES256), so a dirty `git status` after
regeneration is a real change, never noise.
