# Contributing

Two independent reference implementations — Go at `go/` (module root for clean
`go get`), TypeScript at `ts/` (zero runtime deps) — with **no shared code by
design**. The conformance suite is the contract: any change both
implementations must agree on lives in `conformance/vectors/` as a vector.

## Setup

```bash
git clone https://github.com/Daily-Nerd/vitni.git
cd vitni
```

Go 1.21+ and Node 20+ cover the implementations. The conformance-vector
generators are Python, driven by [uv](https://docs.astral.sh/uv/) — no pip,
no manual venvs.

## Tests

```bash
cd go && go test ./...          # Go suite (includes vector-driven tests)
cd ts && npm install && npm run build && npm test
```

## Conformance harness

The cross-implementation check — both verifiers must produce byte-identical
output on every vector:

```bash
mkdir -p bin && (cd go && go build -o ../bin/vitni-verify-go ./cmd/vitni-verify)
(cd ts && npm run build)
node conformance/compare.mjs     # expect: all vectors pass (94/94 as of this change)
```

## Regenerating vectors

Only needed when the wire format changes. Generators are deterministic
(Ed25519 by construction, ES256 via RFC 6979) — regeneration is byte-for-byte
idempotent, so a dirty `git status` after a re-run means a real change:

```bash
cd conformance/vectors
uv run --no-project python _gen.py
uv run --no-project python _gen_a2a.py
uv run --no-project --with cryptography==50.0.2 --with ecdsa==0.19.2 python _gen_verify.py
uv run --no-project --with cryptography==50.0.2 --with ecdsa==0.19.2 python _gen_chain.py
```

The `cryptography` and `ecdsa` pins are the single place the generator
dependency versions live; CI runs the same commands. To check that every
vector is owned by a generator, delete `conformance/vectors/*.json`, rerun the
four commands, and require an empty `git status --porcelain conformance/vectors`.

Every wire-visible feature needs a vector; a wire feature without a Go≡TS
vector is scope creep. Wire literals (`v`, the MCP `_meta` key) flip only in
a protocol revision, never mixed within one.

## CI gates

Every PR runs the conformance harness (`cross-impl`: build both
implementations, run their test suites, then `compare.mjs`) and the PR
convention check (`pr-validation.yml`):

- PR body links an issue labeled `status:approved` (`Closes #N`)
- exactly one `type:*` label on the PR
- conventional-commit title (squash-merge makes it the commit subject)
- branch named `type/description` (lowercase)

Scars-only PRs (`.scars/` moves) skip the issue gates; release-please PRs are
exempt entirely.

## Releases

release-please, whole-repo lockstep: any change to either implementation bumps
the single repo version. Tags `v*` (repo + npm) and `go/v*` (Go module) mint
together; npm publishes via OIDC trusted publishing — no tokens, no manual
steps.
