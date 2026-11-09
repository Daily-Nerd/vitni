# Changelog

All notable changes to vitni are documented here. Format: [Keep a Changelog](https://keepachangelog.com/); versioning: [SemVer](https://semver.org/).

> **One version, one changelog.** vitni ships the Go module and the npm package (`@daily-nerd/vitni`) in lockstep under a single version — any change to either implementation bumps it. release-please generates entries here from conventional commits. The `0.2.0`–`0.2.1` entries (the npm-only transition releases) live in git history — `git show v0.2.2:ts/CHANGELOG.md`; unified history resumes from `0.2.2`.

## [0.6.0](https://github.com/Daily-Nerd/vitni/compare/v0.5.3...v0.6.0) (2026-11-09)


### Features

* **conformance:** profile catalog, profiles command and an n-impl harness ([#71](https://github.com/Daily-Nerd/vitni/issues/71)) ([8972841](https://github.com/Daily-Nerd/vitni/commit/89728414906962475dc9f8380ad76066f16e3bc0))
* **py:** add a stdlib-only reference verifier ([#72](https://github.com/Daily-Nerd/vitni/issues/72)) ([7a885eb](https://github.com/Daily-Nerd/vitni/commit/7a885ebc5e7819ed69e89f32a02e1f6c71a4d118))


### Bug Fixes

* one strict decoder per input format in go and ts ([#69](https://github.com/Daily-Nerd/vitni/issues/69)) ([f629818](https://github.com/Daily-Nerd/vitni/commit/f629818275fff6cebc53c2ecfe004147b52331ea))
* reject invalid utf-8 in sse streams and non-32-byte hashstring digests ([#73](https://github.com/Daily-Nerd/vitni/issues/73)) ([5b5eddb](https://github.com/Daily-Nerd/vitni/commit/5b5eddb4b14604f8a902abdebfcdcffede3cd23e))
* strict stdin gate, exact input typing and surrogate rule for every command ([#77](https://github.com/Daily-Nerd/vitni/issues/77)) ([0c66556](https://github.com/Daily-Nerd/vitni/commit/0c6655695970848109c8a96290cf18979f3dbf7c))

## [0.5.3](https://github.com/Daily-Nerd/vitni/compare/v0.5.2...v0.5.3) (2026-08-14)


### Bug Fixes

* **conformance:** pin ES-number + dispatch-code vectors; stop TS non-finite corruption ([#56](https://github.com/Daily-Nerd/vitni/issues/56)) ([9a2d94c](https://github.com/Daily-Nerd/vitni/commit/9a2d94c4e24ad1e101daeb6655f4af4fe62419e5))
* **ts:** close non-finite bypass in sse-outputs-hash; pin with vectors ([#60](https://github.com/Daily-Nerd/vitni/issues/60)) ([c0744d4](https://github.com/Daily-Nerd/vitni/commit/c0744d4e53609619bc878cf6248b998486c46a90))

## [0.5.2](https://github.com/Daily-Nerd/vitni/compare/v0.5.1...v0.5.2) (2026-07-30)


### Bug Fixes

* align Go/TS base64 decoders — one strict-canonical accept set repo-wide ([#50](https://github.com/Daily-Nerd/vitni/issues/50)) ([98ac39d](https://github.com/Daily-Nerd/vitni/commit/98ac39d6d3cab2731bf3bb431a479b219871e87e)), closes [#49](https://github.com/Daily-Nerd/vitni/issues/49)

## [0.5.1](https://github.com/Daily-Nerd/vitni/compare/v0.5.0...v0.5.1) (2026-07-11)


### Bug Fixes

* republish npm package so the corrected README reaches the npm page ([f9ec0a2](https://github.com/Daily-Nerd/vitni/commit/f9ec0a2f800dc21cd0454e5382025bae65c55301))

## [0.5.0](https://github.com/Daily-Nerd/vitni/compare/v0.4.0...v0.5.0) (2026-07-10)


### Features

* keygen command (Ed25519 keypair generation + JWK derivation) ([#41](https://github.com/Daily-Nerd/vitni/issues/41)) ([35e1741](https://github.com/Daily-Nerd/vitni/commit/35e1741c6609fd789e9acb65e2a11a992214f722))

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
