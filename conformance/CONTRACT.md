# Vitni Conformance Harness — Verifier Contract v0.1

Both the **Go** and **TypeScript** verifiers MUST implement this identical CLI contract.
The harness (`harness/compare.mjs`) runs each vector through **both** binaries and asserts their
stdout is **byte-identical**. Agreement across two independent language runtimes is the proof of
the Draft 0.2 §12 normative guarantee. Divergence is a finding (spec leak or impl bug), not a nuisance.

This harness validates the **byte-source layer** of Vitni (§3–§5, §4.3 of the design draft). It does
NOT yet exercise full signature verification, chains, or the Log — those come once the byte layer is proven.

---

## CLI shape

```
vitni-verify <command> < input.json        # input JSON on stdin
# emits exactly one line of compact JSON to stdout (no trailing newline beyond one \n), exit 0
# on malformed input or unsupported command: emit {"error":"<machine-code>"} to stdout, exit 0
```

Both verifiers MUST:
- Read the entire stdin as the input JSON object.
- Emit output as **JCS-canonical JSON** (so the harness can compare bytes directly), UTF-8, single `\n` terminator.
- Be deterministic. No timestamps, no randomness in output.
- Never print logs/banners to stdout (use stderr if needed).

---

## Commands

### 1. `jcs` — RFC 8785 canonicalization
Input:
```json
{ "value": <any JSON value> }
```
Output:
```json
{ "canonical_hex": "<hex of the JCS UTF-8 bytes>", "byte_len": <int> }
```
- `canonical_hex` = lowercase hex of the exact RFC 8785 canonical octets of `value`.
- Numbers follow RFC 8785 §3.2.2 (ECMAScript `Number` serialization). Strings preserved verbatim (no Unicode normalization).

### 2. `hashstring` — multihash + pinned multibase
Input:
```json
{ "algo": "sha2-256", "digest_hex": "<hex of the raw digest>" }
```
Output:
```json
{ "hashstr": "u<base64url-nopad of multihash(varint code || varint len || digest)>" }
```
- v1 algo: `sha2-256` (multihash code `0x12`). Multibase prefix is the literal char `u` (base64url, no padding).

### 3. `digest` — hash raw bytes into a pinned hash-string
Input:
```json
{ "bytes_b64": "<base64 of the raw input bytes>" }
```
Output:
```json
{ "hashstr": "u..." }
```
- Compute `sha2-256` over the decoded bytes, then multihash + multibase exactly as command 2.

### 4. `receipt-id` — derive the content address of a Receipt
Input:
```json
{ "receipt": <Receipt object WITHOUT a receipt_id field> }
```
Output:
```json
{ "canonical_hex": "<hex of JCS(receipt) octets>", "receipt_id": "u..." }
```
- `receipt_id = "u" + base64url_nopad( multihash_sha256( JCS(receipt) ) )` (design §2, §4.1).
- If the input `receipt` contains a `receipt_id` key, that is an error: `{"error":"receipt_id_must_be_absent"}`.

### 5. `sse-outputs-hash` — the streaming decode-then-hash unit (design §4.3) — HIGHEST RISK
Input:
```json
{ "raw_b64": "<base64 of the raw SSE wire bytes exactly as transmitted>",
  "mode": "sse" | "sse-jsonrpc" }
```
Output:
```json
{ "decoded_hex": "<hex of the committed decoded bytes>", "outputs_hash": "u..." }
```
Decoding rules (MUST match design §4.3 exactly):
- Parse per WHATWG SSE (html.spec.whatwg.org §9.2):
  - Strip a single leading UTF-8 BOM (`EF BB BF`) if present.
  - Normalize line terminators: `\r\n`, lone `\r`, lone `\n` all delimit lines.
  - A `data:` field value is the text after `data:` and an optional single leading space.
  - Multiple `data:` lines within one event join with `\n`; the event's data is that joined string **with no trailing `\n`**.
  - Ignore comment lines (starting `:`) and `event:` / `id:` / `retry:` fields entirely.
  - An event is dispatched on a blank line; an event with empty data is NOT dispatched.
- `committed = UTF8( join(message_data_strings, "\n") )` over dispatched messages, in order.
- For `mode = "sse-jsonrpc"`: each dispatched message `data` is a JSON-RPC message; the committed unit is the **inner `result` value's** JCS octets, concatenated across messages joined by `\n`. (If a message has no `result`, skip it.)
- `outputs_hash` = pinned hash-string of `committed`.

### 6. `cost-canon` — JCS of a cost block with string-encoded integers
Input:
```json
{ "cost": { "tokens": "<decimal-string>", "usd_micros": "<decimal-string>", "wall_ms": "<decimal-string>", "rail_ref": <string|null> } }
```
Output:
```json
{ "canonical_hex": "<hex of JCS(cost) octets>" }
```
- Validates that magnitudes are STRINGS (design §2). If any magnitude is a JSON number, error `{"error":"cost_must_be_string_int"}`.
- Confirms no number-serialization divergence is possible (the 2^53 defense).

---

### 7. `verify` — JWS signature verification + JOSE hardening (design §3, §12 steps 1–6)
Input:
```json
{
  "signed_receipt": "<JWS compact: b64url(header).b64url(payload).b64url(sig)>",
  "keys": {
    "<performer_id>": {
      "<kid>": { "kty": "OKP|EC", "crv": "Ed25519|P-256", "x": "<b64url>", "y": "<b64url, EC only>",
                 "alg": "EdDSA|ES256", "status": "active|revoked" }
    }
  },
  "policy": { "expected_binding": "mcp|a2a|null", "expected_method": "<string|null>" }
}
```
Output:
```json
{ "valid": <bool>, "reason": "<ReasonCode>" }
```

**Verification algorithm (MUST follow exactly; first failing check wins, in THIS order):**
1. `malformed` — JWS not three base64url segments / header or payload not valid JSON / payload not valid UTF-8.
2. `header_key_material` — header contains ANY of `jwk`, `jku`, `x5u`, `x5c`, `x5t`, `x5t#S256` (key material MUST come from the registry, never the token — §12).
3. Resolve key: read `performer_id` from the **payload**, `kid` from the **header**. If `performer_id`/`kid` absent or not in `keys` → `unknown_key`.
4. `revoked_key` — resolved key has `status:"revoked"`.
5. `alg_not_allowed` — header `alg` is `none`/absent, OR header `alg` != the resolved key's `alg` (no alg-substitution; `none` always rejected).
6. `bad_signature` — signature does not verify under the resolved key over `b64url(header).b64url(payload)`. (ES256 signature is raw R‖S, 64 bytes, per JWS; Ed25519 is EdDSA.)
7. `non_canonical_payload` — `base64url-decode(payload)` != `JCS(parse(payload))` byte-for-byte (the §3 JWS≡JCS invariant — reject a validly-signed but non-canonical payload).
8. `context_mismatch` — `policy.expected_binding`/`expected_method` set and != the payload's `binding`/`method`.
9. Else `{ "valid": true, "reason": "ok" }`.

Any failure → `{ "valid": false, "reason": "<code>" }`. Output JSON MUST be JCS-canonical.

### 8. `verify-chain` — full-chain (lineage path) verification (design §7, §12 step 9)
Input:
```json
{
  "receipts": ["<JWS leaf>", "<JWS parent>", "...", "<JWS root>"],
  "keys": { "<performer_id>": { "<kid>": { ...as in §7... } } },
  "policy": { "expected_binding": "mcp|a2a|null", "expected_method": "<string|null>" }
}
```
- `receipts` is an ordered **leaf→root path** (index 0 = the leaf action being audited; the last = the chain root).
- The full DAG validates as independent paths; this command validates ONE path.

Output:
```json
{ "valid": <bool>, "reason": "<ChainReasonCode>", "chain_len": <int> }
```

**Algorithm (first-failing-check-wins, in THIS order):**
1. `empty_chain` — `receipts` is empty.
2. For each receipt i (leaf→root): run the full §7 `verify` (resolve key, JOSE hardening, signature, `non_canonical_payload`). `policy` is applied to the **leaf only** (i=0). Any failure → `receipt_invalid` (the chain is only as trustworthy as each hop).
3. Compute `receipt_id[i] = "u"+base64url(multihash(JCS(payload_i)))` for each.
4. `malformed_chain` — any non-root hop (i < n-1) has `parent_receipt_hash == null`, OR the root hop (i = n-1) has `parent_receipt_hash != null` (a claimed-but-unprovided parent = dangling).
5. `link_mismatch` — for any i < n-1, `receipts[i].parent_receipt_hash != receipt_id[i+1]`.
6. `parent_identity_mismatch` — for any i < n-1 where `receipts[i].parent_performer_id` is present and non-null, it != `receipts[i+1].performer_id`.
7. `cycle` — any `receipt_id` value appears more than once in the path.
8. Else `{ "valid": true, "reason": "ok", "chain_len": n }`.

Any failure → `{ "valid": false, "reason": "<code>", "chain_len": n }`. Output JSON MUST be JCS-canonical.

### 9. `a2a-artifact-hash` — A2A artifact canonicalization → outputs_hash (design §14)
A2A does not define artifact-level canonicalization, so Vitni defines it. Input:
```json
{ "artifact": { "parts": [ <A2A Part>, ... ] } }
```
where each `Part` is one of (A2A shapes):
- `{ "kind": "text", "text": "<string>" }`
- `{ "kind": "data", "data": <any JSON object> }`
- `{ "kind": "file", "file": { "bytes": "<base64>", "mimeType": "<string>", "name": "<string>" } }`  (inline)
- `{ "kind": "file", "file": { "uri": "<string>", "mimeType": "<string>", "name": "<string>" } }`  (by-reference)

Output:
```json
{ "outputs_hash": "u...", "descriptor_hex": "<hex of the canonical descriptor JCS bytes>" }
```

**Canonicalization rule (MUST match exactly):** map each part — preserving array order — to a canonical **descriptor**, then hash the descriptor list:
- `text`  → `{ "kind": "text", "text": <text> }`
- `data`  → `{ "kind": "data", "data": <data> }`
- `file` inline (`bytes` present) → `{ "kind": "file", "digest": multihash(decoded_bytes), "mimeType": <m|null>, "name": <n|null> }`  (hash the bytes, do NOT embed them)
- `file` by-uri (`uri` present, no `bytes`) → `{ "kind": "file", "uri": <uri>, "declared_digest": <the file's declared digest hash-string, or null>, "mimeType": <m|null>, "name": <n|null> }`  (NEVER dereferenced — §4.4)
- A part with neither `bytes` nor `uri`, or an unknown `kind` → error `{"error":"unsupported_part"}`.

`descriptor = { "parts": [ <descriptor_0>, ... ] }`; `descriptor_hex = hex(JCS(descriptor))`; `outputs_hash = multihash(JCS(descriptor))` (pinned hash-string, §4.1). A receipt for an A2A task sets `binding:"a2a"`, `method:"a2a:<skill>"`, and this `outputs_hash`.

## Vector file format (`vectors/*.json`)
```json
{
  "name": "jcs/sorted-keys",
  "command": "jcs",
  "input": { "value": { "b": 1, "a": 2 } },
  "anchor": { "canonical_hex": "7b2261223a322c2262223a317d", "byte_len": 13 }
}
```
- `anchor` is OPTIONAL. When present it is an externally-known-correct expected output (e.g. an RFC 8785 test value or a hand-computed digest). The harness asserts BOTH verifiers match the anchor AND each other.
- When `anchor` is absent, the harness asserts only that the two verifiers agree with each other (catches ambiguity; does not catch both-wrong-the-same-way — that is what anchors are for).

## Harness output
`harness/compare.mjs` prints, per vector: `PASS` (both agree, anchor matched if present), `DIVERGE` (verifiers disagree — prints both outputs), or `ANCHOR-FAIL` (agree with each other but not the known-correct anchor). Exit non-zero if any vector is not PASS.
