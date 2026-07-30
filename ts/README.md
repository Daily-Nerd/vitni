# @daily-nerd/vitni

**vitni** (Old Norse: *witness*) — signed, tamper-evident execution receipts for AI agents, under MCP and beside A2A.

When an agent performs an action, the performer emits a small, signed, content-addressed **receipt** of what it did, what it returned, and what it cost. Anyone can verify that receipt independently — offline — walk a multi-hop chain of them, and replay the attested timeline.

Zero runtime dependencies (`node:crypto` only). Byte-identical with the independent [Go implementation](https://github.com/Daily-Nerd/vitni/tree/main/go) on a public conformance suite.

## Install

```sh
npm i @daily-nerd/vitni
```

## Use

```ts
import { signCommand, verify, hashOf } from "@daily-nerd/vitni";

// the performer signs what it did (signCommand: seed-in-hand signing;
// MCP servers use the vitniToolResult middleware instead — see quickstart)
const { signed_receipt } = signCommand({
  receipt: {
    binding: "mcp",
    method: "mcp:add",
    performer_id: "srv-demo",
    inputs_hash: hashOf(params),
    outputs_hash: hashOf(result),
    cost: { tokens: "0", usd_micros: "0", wall_ms: "3", rail_ref: null },
    // ...see the spec for the full receipt object
  },
  kid: "key-1",
  private_key_b64: myEd25519SeedB64,   // 32-byte Ed25519 seed, base64
});

// anyone verifies it independently — offline
const verdict = verify({ signed_receipt, keys });  // -> { valid: true, reason: "ok" }
```

MCP servers: attach receipts to tool results via the co-signing middleware (one `_meta` field, no transport changes). A2A: artifact-metadata binding. See the [quickstart](https://github.com/Daily-Nerd/vitni/blob/main/docs/QUICKSTART.md).

## CLI

The package ships `vitni-verify` — a standalone CLI (JSON on stdin, one JCS-canonical line on stdout) covering keygen, signing, verification, and the conformance commands:

```sh
echo '{}' | vitni-verify keygen        # Ed25519 keypair + ready-to-paste verify JWK
vitni-verify verify < verify-input.json
```

## What it proves — and what it does NOT

**Proves:** performer non-repudiation, response-byte integrity, verifiable cost, tamper-evident multi-hop lineage.

**Does NOT prove:** that the action was correct or non-hallucinated, that a world side-effect happened, or intent integrity. It is *check-me, not trust-me*.

## Links

- **Spec:** [DESIGN.md](https://github.com/Daily-Nerd/vitni/blob/main/docs/DESIGN.md) — receipt object, canonicalization (RFC 8785 JCS), verification algorithm, chain semantics, bindings
- **Conformance suite:** language-agnostic vectors; any implementation that passes is interoperable
- **Repository:** https://github.com/Daily-Nerd/vitni

Apache-2.0.
