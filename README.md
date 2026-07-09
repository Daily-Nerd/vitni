<h1 align="center">vitni</h1>
<p align="center"><em>The witness to agent actions.</em> (Old Norse: <em>vitni</em>, witness — formerly <strong>veritrail</strong>.)</p>
<p align="center">Signed, tamper-evident execution receipts for AI agents — under MCP and beside A2A.</p>

<p align="center">
  <a href="https://github.com/Daily-Nerd/vitni/actions/workflows/conformance.yml"><img src="https://github.com/Daily-Nerd/vitni/actions/workflows/conformance.yml/badge.svg" alt="conformance"></a>
  <a href="https://codecov.io/gh/Daily-Nerd/vitni"><img src="https://codecov.io/gh/Daily-Nerd/vitni/graph/badge.svg?token=bkJnBEV2yF" alt="codecov"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/conformance-57%2F57-brightgreen" alt="conformance 57/57">
</p>

---

> **Status: early / design-validated.** The protocol and a two-language reference (Go + TypeScript) are validated byte-for-byte against a conformance suite. APIs will change before `v1`. See [ROADMAP](ROADMAP.md).
>
> **Wire string:** receipts carry `v: "vitni/0.2"` as of protocol revision 0.2. Receipts signed under the pre-rename `veritrail/0.1` remain verifiable — verification never inspects `v` — but new receipts always stamp the current string.

## What it is

When an AI agent performs an action — a tool call, a task, a step in a chain — **vitni** lets the party that *performed* it emit a small, signed, content-addressed **receipt** of what it did, what it returned, and what it cost. Anyone can later **verify** that receipt independently, walk a multi-hop **chain** of them, and **replay** the attested timeline.

It is the difference between *"trust me, here's a summary"* and *"check me — here's a record you can verify."*

```ts
import { sign, verify } from "@daily-nerd/vitni";

// the performer signs what it did
const receipt = await sign(key, {
  binding: "mcp",
  method: "mcp:add",
  inputs_hash:  hashOf(params),
  outputs_hash: hashOf(result),
  cost: { tokens: "0", usd_micros: "0", wall_ms: "3", rail_ref: null },
});

// anyone verifies it independently — offline
const verdict = await verify(receipt, { keys });   // -> { valid: true, reason: "ok" }
```

```sh
$ vitni-verify verify < receipt.json
  valid: true  reason: ok
```

## Why depend on it instead of rolling your own

Getting receipts *right* is deceptively hard — deterministic canonicalization, signature verification that resists the classic JOSE attacks, chain integrity that resists splicing. vitni ships that, proven:

- **Deterministic by construction** — RFC 8785 JCS canonicalization, proven **byte-identical across two independent implementations** (Go + TS) on a public conformance suite. Two verifiers always agree.
- **Hardened verification** — Ed25519 + ES256 (JWS), with the dangerous paths closed: rejects `alg:none`, algorithm substitution, `jwk`/`jku`/`x5*` header key-injection, non-canonical payloads, unknown/revoked keys.
- **Chain integrity** — multi-hop receipts link `parent → child` into a tamper-evident lineage, with a `parent_performer_id` binding that defeats foreign-parent splicing.
- **Rides the existing rails** — one `_meta` field on an MCP tool result; one artifact-metadata entry on an A2A task. **No new transport, no extra round-trip.** A client that doesn't understand it ignores it.

## What it proves — and what it does NOT (honest boundary)

**Proves:** performer non-repudiation, response-byte integrity, which authorization token was referenced (by hash), and verifiable cost. A receipt cannot be altered after signing without detection, and a multi-hop chain shows who-did-what-under-whom.

**Does NOT prove:** that the action was *correct* or *non-hallucinated*; that a world side-effect actually happened; *intent integrity* (a prompt-injected-but-authorized request still produces a valid receipt). vitni attests *what the performer did and returned* — it is **check-me, not trust-me**, not a proof the outcome was right. We will never market it beyond that line.

## Layers

```
your agent / tool / MCP server / A2A skill
        │  emits a signed receipt on each action
        ▼
   vitni receipt  ──►  verify (offline)  ──►  chain / replay  ──►  [optional] transparency log
```

## Install

**Go — live:**
```sh
go get github.com/Daily-Nerd/vitni/go@latest                              # library (requires go/v0.3.0+ — earlier tags predate the rename)
go install github.com/Daily-Nerd/vitni/go/cmd/vitni-verify@latest     # CLI (binary: vitni-verify; requires go/v0.3.0+)
```
```go
import "github.com/Daily-Nerd/vitni/go"   // package vitni → vitni.Sign(...), vitni.Verify(...)
```

**npm — live** as **`@daily-nerd/vitni`** from `0.3.0` (published as `@daily-nerd/veritrail` for `0.1.1`–`0.2.2`):
```sh
npm i @daily-nerd/vitni
```

## Quickstart

New here? **[docs/QUICKSTART.md](docs/QUICKSTART.md)** takes you from install to a signed, independently-verifiable receipt — the production MCP co-signing path plus a local `sign | verify` round-trip with the CLI.

## Spec & conformance

- **[docs/DESIGN.md](docs/DESIGN.md)** — the full protocol: receipt object, canonicalization, signing, the verification algorithm, chain semantics, MCP/A2A bindings, threat model.
- **Conformance vectors** — a language-agnostic suite; any implementation that passes is interoperable. (Porting in — see ROADMAP.)

## License

[Apache-2.0](LICENSE). Build on it.
