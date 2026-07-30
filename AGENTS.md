# AGENTS.md

## Project Overview

vitni is a cryptographic execution-receipt protocol for
AI agents: signed, tamper-evident, content-addressed receipts under MCP and
beside A2A. Two independent reference implementations (Go at `go/`,
TypeScript at `ts/`) share no code; `conformance/vectors/` is the contract
between them. The spec is `docs/DESIGN.md`.

## Agent Contract

- The conformance suite is load-bearing: any wire-visible change needs a
  Go≡TS vector and a green `node conformance/compare.mjs` before it ships.
- Wire literals (protocol version `v`, MCP `_meta` key) flip only in a
  protocol revision and always together — never mix names within one version.
- Vector generators are deterministic (RFC 6979 for ES256); if regenerating
  dirties `git status`, that is a real change, not noise.
- Scars: `.scars/` records negative knowledge. New scars go to
  `.scars/candidates/` only (mandatory YAML frontmatter); a human promotes.
  Honor injected scars unless the user overrides.
- Planning artifacts (plans, briefs, ledgers) never land in this repo — they
  live in the maintainer's Obsidian vault or ephemeral scratch space.

## Development Commands

- Go tests: `cd go && go test ./...`
- TS tests: `cd ts && npm install && npm run build && npm test`
- Cross-impl harness: build both, then `node conformance/compare.mjs` (all vectors must pass — 79 as of this change)
- Vector regeneration: `uv run` only — see CONTRIBUTING.md (never pip/bare python)

## Repository Rules

- Do not add AI attribution or `Co-Authored-By` lines to commits.
- Conventional commit messages; PR title becomes the squash-merge subject.
- Issue-first flow: PRs link an issue labeled `status:approved`; exactly one
  `type:*` label per PR; branches named `type/description` (lowercase).
- Do not build after changes unless running the test/conformance gates above.
- CHANGELOG.md belongs to release-please — never edit it by hand.
- Zero runtime dependencies in the published TS bundle; Go carries only
  `github.com/gowebpki/jcs`. New runtime deps need a strong architectural
  reason.
