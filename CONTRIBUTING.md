# Contributing

Two independent full reference implementations (Go at `go/`, the module root
for a clean `go get`, and TypeScript at `ts/`, zero runtime deps) with **no
shared code by design**, plus a verify-only Python verifier (`py/vitni_verify.py`,
one file, standard library only). The conformance suite is the contract: any
change the implementations must agree on lives in `conformance/vectors/` as a
vector.

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
uv run --no-project --python 3.10 python -I -m unittest discover -s py/tests -t py
uv run --no-project --python 3.13 python -I -m unittest discover -s py/tests -t py
```

The Python suite needs nothing but the standard library (and `node`, which the
number-layout differential test runs; a missing `node` is a failure, not a
skip). A second-oracle check against the `cryptography` package lives apart in
`py/tests_cross` so the gating suite stays stdlib only:

```bash
uv run --no-project --python 3.13 --with cryptography==50.0.2 python -I -m unittest discover -s py/tests_cross -t py
```

## Conformance harness

The cross-implementation check: every verifier must produce byte-identical
output on every vector it declares (the Python verifier declines the commands it
does not implement with an exact `unsupported_profile`):

```bash
mkdir -p bin && (cd go && go build -o ../bin/vitni-verify-go ./cmd/vitni-verify)
(cd ts && npm run build)
REQUIRE_IMPLS=go,ts,py PY_VERIFY="uv run --no-project --python 3.13 python -I py/vitni_verify.py" node conformance/compare.mjs
# expect: `impls: go ts py` and all vectors pass (the harness prints the count)
```

`REQUIRE_IMPLS` is the one list of implementations that must run: a listed
implementation that did not run fails the harness (`IMPL-MISSING`), so dropping
one is not a smaller run. CI sets `REQUIRE_IMPLS=go,ts,py` and runs the command
above on both Python 3.10 and 3.13. Without it, `node conformance/compare.mjs`
runs Go and TypeScript, adds Python when `PY_VERIFY` is set, and checks each
floor in `floors.json` for the implementations that ran, so a Go and TypeScript
only run needs no Python.

## Vendoring the Python verifier

`py/vitni_verify.py` is one file with no dependencies, meant to be copied into
another project:

- Fetch it at a release tag, never `main`, and store its sha256
  (`shasum -a 256 py/vitni_verify.py`) in a test constant that hashes your copy
  and fails on a mismatch. The file carries no version stamp, so a release that
  does not touch it keeps the same hash.
- Give your copy `eol=lf` in `.gitattributes` (`py/vitni_verify.py text eol=lf`
  here) and do not run a formatter over it: any byte change changes the hash.
- Run it as `python -I vitni_verify.py <command>`, or import `verify`. The
  result line says what happened: `{"valid":true}` is verified,
  `{"valid":false}` is failed, and any `{"error":...}` is unable (no judgement
  was made).
- ES256 is raw R||S (64 bytes), never DER. Commands it does not implement
  (`sign`, `keygen`, `verify-chain`, `sse-outputs-hash`, `a2a-artifact-hash`,
  `cost-canon`) answer `unsupported_profile` without reading stdin.

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
