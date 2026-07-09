# Changelog

All notable changes to veritrail are documented here. Format: [Keep a Changelog](https://keepachangelog.com/); versioning: [SemVer](https://semver.org/).

> **One version, one changelog.** vitni (formerly veritrail) ships the Go module and the npm package (`@daily-nerd/vitni`) in lockstep under a single version — any change to either implementation bumps it. release-please generates entries here from conventional commits. The `0.2.0`–`0.2.1` entries (the npm-only transition releases) live in git history — `git show v0.2.2:ts/CHANGELOG.md`; unified history resumes from `0.2.2`.

## [0.4.0](https://github.com/Daily-Nerd/vitni/compare/v0.3.0...v0.4.0) (2026-07-09)


### ⚠ BREAKING CHANGES

* protocol vitni/0.2 — local binding, ext field, wire-literal flip, 47 vectors ([#25](https://github.com/Daily-Nerd/vitni/issues/25))

### Features

* protocol vitni/0.2 — local binding, ext field, wire-literal flip, 47 vectors ([#25](https://github.com/Daily-Nerd/vitni/issues/25)) ([6b1708e](https://github.com/Daily-Nerd/vitni/commit/6b1708eb9407c7275f9a2751d64aef147b3de84a))


### Bug Fixes

* **go:** empty-string parent_performer_id is a carried lineage claim ([#38](https://github.com/Daily-Nerd/vitni/issues/38)) ([e1cb638](https://github.com/Daily-Nerd/vitni/commit/e1cb638b8461d6ffabd18650b4876c0801771eeb))
* reject unknown top-level keys + non-string cost at sign; reject duplicate keys (§4.1) ([#39](https://github.com/Daily-Nerd/vitni/issues/39)) ([b4ef643](https://github.com/Daily-Nerd/vitni/commit/b4ef643a68cf7b86233bedc6256be267e701ed44)), closes [#34](https://github.com/Daily-Nerd/vitni/issues/34)
* **ts:** strict input decode to match Go + spec §4.1 ([#35](https://github.com/Daily-Nerd/vitni/issues/35)) ([0d8e713](https://github.com/Daily-Nerd/vitni/commit/0d8e713fe8cc5f79f63fe433ef9ac66cb72880ad))

## [0.3.0](https://github.com/Daily-Nerd/vitni/compare/v0.2.2...v0.3.0) (2026-07-09)


### ⚠ BREAKING CHANGES

* Go module path, Go package name, npm package name, bin name, and two exported TS symbols are renamed.

### Features

* rename project to vitni (formerly veritrail) ([#22](https://github.com/Daily-Nerd/vitni/issues/22)) ([7b22f9f](https://github.com/Daily-Nerd/vitni/commit/7b22f9f8395f209ceb89bed0d45a7b4b7f4c4137))

## [0.2.2](https://github.com/Daily-Nerd/veritrail/compare/v0.2.1...v0.2.2) (2026-06-12)


### Bug Fixes

* **ts:** derive protocol version from a single shared constant ([#20](https://github.com/Daily-Nerd/veritrail/issues/20)) ([a67586c](https://github.com/Daily-Nerd/veritrail/commit/a67586c1eed2daa1326d6d693a693ed6f73e5642))

## [0.1.1] — 2026-05-29

### Changed
- **npm package name:** the TypeScript implementation publishes as **`@daily-nerd/veritrail`**. The bare `veritrail` name is taken on npm by an unrelated package, so the scoped name is final. The `veritrail-verify` CLI binary name is unchanged.
- **Go module layout:** the library package moved to the module root. The import path is now `github.com/Daily-Nerd/veritrail/go` (was `…/go/veritrail`) — use `veritrail.Sign(...)`, `veritrail.Verify(...)`. Install the CLI with `go install github.com/Daily-Nerd/veritrail/go/cmd/veritrail-verify@v0.1.1`. (v0.1.0's nested import path is superseded; behavior and conformance unchanged — still 41/41 Go ≡ TS.)

## [0.1.0] — 2026-05-29

Initial reference release. Protocol version `veritrail/0.1`.

**Release status:** Go module **live** (`go get github.com/Daily-Nerd/veritrail/go@v0.1.0`, tag `go/v0.1.0`). npm publish **pending** (awaiting the npm org / final package-name decision: `veritrail` vs `@daily-nerd/veritrail`).

### Added
- **Receipt protocol** — performer-attested, content-addressed execution receipts for AI agent actions (`docs/DESIGN.md`).
- **Two reference implementations**, byte-identical across runtimes:
  - Go (`github.com/Daily-Nerd/veritrail/go`) — `Sign`, `Verify`, `VerifyChain`, `A2AArtifactHash`, `JCS`, `HashString`, `Digest`, `ReceiptID`, `SSEOutputsHash`, `CostCanon` + `veritrail-verify` CLI.
  - TypeScript (`veritrail`) — `sign`, `verify`, `verifyChain`, `a2aArtifactHash`, JCS/hash-string helpers, receipt types, and MCP + A2A co-signing middleware. Zero runtime dependencies.
- **RFC 8785 JCS** canonicalization with a pinned multibase hash-string encoding.
- **Signing & hardened verification** — Ed25519 + ES256 (JWS); rejects `alg:none`, algorithm substitution, `jwk`/`jku`/`x5*` header key-injection, non-canonical payloads, unknown/revoked keys.
- **Chain / DAG verification** with `parent_performer_id` foreign-splice defense.
- **MCP binding** (`result._meta["dev.veritrail/receipt"]`) and **A2A binding** (artifact metadata + artifact-canonicalization).
- **SSE** decode-then-hash streaming commitment.
- **Conformance suite** — 41 language-agnostic vectors + reproducible generators + cross-implementation harness; enforced in CI (Go ≡ TS, byte-identical).

### Notes
- Honest value cap: veritrail attests *what a performer did and returned* — performer non-repudiation, byte integrity, authorization-binding-by-hash, verifiable cost. It does **not** prove correctness, world side-effects, or intent integrity.
- APIs may change before `1.0`.
