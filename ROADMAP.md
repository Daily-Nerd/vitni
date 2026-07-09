# Roadmap

vitni is an **OSS dependency** play: the goal is to be the trustworthy, hardened, multi-language primitive other tools and frameworks *depend on* for signing and verifying agent execution receipts — not a product you buy. Success = real integrations, not stars.

## Validated (design + reference, pre-extraction)

The protocol and a two-language reference were built and validated cold against a cross-implementation conformance harness (Go ≡ TypeScript, byte-identical, externally-anchored):

- ✅ Receipt object + RFC 8785 JCS canonicalization (pinned hash-string encoding)
- ✅ Ed25519 + ES256 (JWS) signing + hardened verification (alg:none / alg-substitution / `jwk`/`jku`/`x5*` injection / non-canonical payload / unknown/revoked key)
- ✅ Chain / DAG verification + `parent_performer_id` foreign-splice defense
- ✅ MCP binding (end-to-end vs the real MCP SDK) and A2A binding (vs the real A2A SDK)
- ✅ Streaming (SSE) decode-then-hash commitment

## Now: make it a real dependency

- [ ] Extract a clean `vitni` library API (separate from harness/demo code), Go + TS
- [ ] Publish packages: npm (`vitni`), Go module (`github.com/Daily-Nerd/vitni/go`)
- [ ] Port the conformance vector suite into `conformance/` (regenerated at `vitni/0.2`)
- [ ] CI: cross-impl conformance must pass on every commit
- [ ] `vitni` CLI: `sign`, `verify`, `verify-chain`
- [ ] One-line adoption surface: middleware decorators for MCP servers / A2A providers
- [ ] Quickstart + DX docs

## Next: distribution-by-integration

The hard truth: a free dependency with weak organic demand wins by being *carried*, not found. Priorities:

- [ ] Get carried by an agent framework / MCP-or-A2A SDK as the reference receipt layer
- [ ] Align with the in-flight IETF agent-receipt / audit-trail drafts — be the reference implementation, not a competitor
- [ ] PyPI (`vitni`) third reference implementation

## Later (optional, only if it earns ubiquity)

- [ ] Transparency log (L2): RFC 6962-style witnessed Merkle log + inclusion proofs (the cross-org / high-assurance layer)
- [ ] Full DAG fan-out; richer cost-attribution tooling

## Honest watch-items

- **Absorption:** native receipt fields in MCP/A2A, or an incumbent governance toolkit, could commoditize the primitive. Be the obvious dependency *before* that — and stay the best-engineered, most-conformant one.
- **Scope discipline:** vitni signs and verifies *what a performer did*. It is not an observability platform, an AI code reviewer, or a governance suite. Stay a primitive. 
