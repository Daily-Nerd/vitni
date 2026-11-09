# Vitni Conformance Harness: Verifier Contract

All conforming implementations MUST implement this identical CLI contract. The Go and
TypeScript references are always run; further implementations (a Python verifier, for one)
register in the harness and run beside them. The harness (`conformance/compare.mjs`) runs each
vector through every registered implementation and asserts that every implementation in scope
prints **byte-identical** stdout. Agreement across independent runtimes is the proof of
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

Every conforming verifier MUST:
- Read the entire stdin as the input JSON object.
- Emit output as **JCS-canonical JSON** (so the harness can compare bytes directly), UTF-8, single `\n` terminator.
- Be deterministic. No timestamps, no randomness in output.
- Never print logs/banners to stdout (use stderr if needed).

---

## Input strictness (normative)

Every external byte string enters through ONE strict decoder per format, and the CLI judges stdin once, before any command logic. The order is fixed:

1. **Missing command**: no command argument is `{"error":"missing_command"}`. An empty string is an argument: it is an unknown command (rule 2).
2. **The command resolves first.** An unknown command is `{"error":"unsupported_command"}` whatever the stdin is; stdin is never parsed for it.
3. **The stdin gate**, the same for EVERY command (`jcs hashstring digest receipt-id sse-outputs-hash cost-canon verify verify-chain a2a-artifact-hash sign keygen`), `verify` and `verify-chain` included. The stdin bytes must be strict UTF-8 text (no overlong forms, no encoded surrogates), without a leading BOM (`EF BB BF`), free of lone-surrogate `\uXXXX` escapes in any key or string (a valid surrogate pair escape is fine), exactly one JSON value followed only by optional ASCII whitespace (so no trailing garbage or NUL), nested at most 128 deep (the top-level object is depth 1), without a number that overflows a float64 to infinity, and the value must be a JSON object. Duplicate object keys are rejected over the whole text for `jcs`, `receipt-id` and `cost-canon`, and are last-wins for every other command. Any violation is `{"error":"invalid_input"}`. Empty stdin is invalid input too: it is not a JSON value.
4. **Member names and types.** Member names are exact and case-sensitive; a name that differs only in case is an unknown member and is ignored. A required member that is absent or `null`, or any member of the wrong JSON type, is `{"error":"invalid_input"}`. Unknown members are ignored, so the input can grow. The one required member whose domain includes `null` is `jcs` `value`: the key must be present, `null` is a value. For `verify` and `verify-chain` the WHOLE `keys` tree is typed (every performer an object or `null`, every entry an object or `null`, `kty crv x y alg status` each a string, `null` or absent) and `policy` (an object or `null`, `expected_binding` and `expected_method` each a string, `null` or absent), not only the entry a receipt resolves to. A `null` registry entry is absent: `unknown_key`. The members each command reads, their types and which are required are in the table below; what a command does with a member stays in the command.
5. The command runs on input that has passed 3 and 4.

| Command | Members (R = required, absent or `null` is `invalid_input`) |
|---|---|
| `jcs` | `value` any JSON value (R, key presence, `null` is a value) |
| `hashstring` | `algo` string (R, exactly `sha2-256`), `digest_hex` string (R) |
| `digest` | `bytes_b64` string (R) |
| `receipt-id` | `receipt` object (R) |
| `sse-outputs-hash` | `raw_b64` string (R), `mode` string (R, `sse` or `sse-jsonrpc`) |
| `cost-canon` | `cost` object (R) |
| `verify` | `signed_receipt` string or `null` (absent is `malformed`), `keys` object or `null`, `policy` object or `null` |
| `verify-chain` | `receipts` array of strings or `null` (absent is `empty_chain`), `keys`, `policy` as `verify` |
| `a2a-artifact-hash` | `artifact` object (R) with `parts` array of objects (R); each part `kind` string or `null`, `file` object or `null` with `bytes`, `uri`, `mimeType`, `name` each string or `null` |
| `sign` | `receipt` object (R), `kid` string or `null` (absent is `kid_required`), `private_key_b64` string or `null` (absent is `invalid_private_key`) |
| `keygen` | `seed_b64` judged by the command (a non-string is `invalid_seed`, any other member is `invalid_input`) |

A problem in the stdin text or in its shape is a **command error** (`invalid_input`), never a verdict. A problem inside the signed envelope (the JWS segments, header, payload) is a `verify` verdict (`malformed`, `alg_not_allowed`, ...). `internal_error` and `jcs_output_error` MUST be unreachable from any stdin bytes.

Text policy by site (the contract all implementations follow):

| Site | Encoding | Lone surrogate escape | Duplicate keys | Non-finite number | Depth over 128 | Top level | Error |
|---|---|---|---|---|---|---|---|
| stdin, every command | UTF-8, no BOM, strict | reject | reject for `jcs`, `receipt-id`, `cost-canon` over the WHOLE text; last-wins otherwise | reject anywhere in the text | reject | object | `invalid_input` |
| JWS header (verify step 1) | same | reject | last-wins | accept (never serialized) | reject | object | `malformed` |
| JWS payload (verify step 1) | same | reject | last-wins at parse; step 7 re-serialization differs, so `non_canonical_payload` | defer: step 7 fails, so `non_canonical_payload` | reject | object | `malformed` (step 1) |
| embedded JSON (`sse-jsonrpc` inner message) | same | reject | last-wins | reject | reject | any | `invalid_input` |

The embedded row covers every re-parse of JSON text hidden inside another input: a guard at one boundary does not cover a second parse site. The depth limit is the protocol's, never the host parser's: nesting over 128 is rejected even where the host parser would stop calling the text JSON at all. An inner message that is not JSON at all is skipped (see `sse-outputs-hash`). `a2a-artifact-hash` parts are members of the stdin object, so the stdin gate already judges them.

---

## Profiles, declined commands and coverage

A verifier states what it implements; the harness holds it to that statement. The pieces:

- **Catalog.** `conformance/profiles.json` is the single list of profile atoms (`alg:EdDSA`, `alg:ES256`, `canon:jcs`, `canon:b64-strict`, plus the non-gating `binding:mcp` and `binding:local`). An atom exists only if the catalog lists it; a new algorithm or canonicalization adds one row there and nothing else.
- **Vector tags.** Every vector carries a `profiles` member: the sorted, unique catalog atoms the vector needs. The generators compute it from the vector's own data (`conformance/vectors/_profiles.py`); it is never written by hand. `cmd:<command>` atoms are derived from the `command` member and are never stored.
- **The `profiles` command.** `vitni-verify profiles` ignores stdin entirely (junk, empty or closed) and prints one JCS line: the sorted array of the GATING atoms the verifier implements, for Go and TypeScript `["alg:ES256","alg:EdDSA","canon:b64-strict","canon:jcs"]`. It is infrastructure, not a vector command: it appears in no vector, and it is outside the stdin gate. A declaration lists gating atoms only (a non-gating atom can never change a vector's scope) and never a `cmd:` atom.
- **Scope.** For one vector and one implementation, `missing` is the vector's gating atoms the implementation did not declare. If `missing` is not empty the implementation MUST print exactly `{"error":"unsupported_profile","profile":"<atom>"}` and exit 0, where `<atom>` is one of the missing atoms or `cmd:<command>`. If `missing` is empty it MUST answer, except that an implementation which does not implement a whole command declines every vector of that command with `{"error":"unsupported_profile","profile":"cmd:<command>"}` (checked before any atom, and without reading stdin). A decline is exactly that object: no other member, a `profile` that is a string naming an atom. The harness checks that `profile` is a string and one of the allowed values above (membership only); it does not require a particular one when several apply. A command is declined for all of its vectors or for none.
- **Distinct codes.** `unsupported_profile` is never `unsupported_command` (a command nobody implements) and never `missing_command`: the harness fails an implementation that declines a vector whose anchor is one of those two CLI errors. An alg outside the algorithm table, in a header or in the registry, is still the verdict `alg_not_allowed` (the key-type binding rule in `verify`, step 5), never a profile decline.
- **Never silent.** An in-scope vector must be answered, byte-identically to every other answering implementation and matching its anchor. Answering an out-of-scope vector, printing nothing, exiting non-zero or printing anything but the exact decline all fail the run.
- **Floors.** `conformance/floors.json` maps each registered implementation to a lower bound on the vectors it answers: the literal `"all"` (answered equals the total, used for Go and TypeScript) or a non-negative integer. A floor is a lower bound, so answering more is fine. Floors are checked for the implementations that ran, and an implementation that ran must have one. Which implementations must run is a separate, single list: the environment variable `REQUIRE_IMPLS` (comma separated, for example `go,ts,py`; CI sets it). A listed implementation that did not run is `IMPL-MISSING`, so removing one from a CI run is a failure, not a smaller run; with `REQUIRE_IMPLS` unset or empty, any subset that has floors may run.
- **The count.** The number of vectors is computed by the harness and printed as `vectors: N`; no document states it.

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
- `digest_hex` must decode to exactly 32 bytes: the multihash header declares length `0x20`, so any other length (including empty) is `invalid_input`.

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
- The decoded stream must be valid UTF-8 end to end, judged before any framing: an invalid sequence anywhere (a `data:` line, a comment, an ignored field, an undispatched tail, after a BOM; stray, truncated or overlong bytes, an encoded surrogate) is `invalid_input` in both modes. Nothing is hashed as raw bytes and nothing is replaced with U+FFFD.
- Parse per WHATWG SSE (html.spec.whatwg.org §9.2):
  - Strip a single leading UTF-8 BOM (`EF BB BF`) if present.
  - Normalize line terminators: `\r\n`, lone `\r`, lone `\n` all delimit lines.
  - A `data:` field value is the text after `data:` and an optional single leading space.
  - Multiple `data:` lines within one event join with `\n`; the event's data is that joined string **with no trailing `\n`**.
  - Ignore comment lines (starting `:`) and `event:` / `id:` / `retry:` fields entirely.
  - An event is dispatched on a blank line; an event with empty data is NOT dispatched.
- `committed = UTF8( join(message_data_strings, "\n") )` over dispatched messages, in order.
- For `mode = "sse-jsonrpc"`: each dispatched message `data` is a JSON-RPC message; the committed unit is the **inner `result` value's** JCS octets, concatenated across messages joined by `\n`. (If a message has no `result`, skip it. If a message is not JSON at all, skip it.) A message that is JSON goes through the strict text policy of the embedded-JSON row above over the WHOLE message, not only `result`: a lone-surrogate escape, a non-finite number or nesting over 128 anywhere in it rejects the command with `invalid_input`. Nesting over 128 is judged before the "is it JSON" question.
- `mode` is exactly `"sse"` or `"sse-jsonrpc"`; any other value, a missing `mode` or `raw_b64`, or a non-string is `invalid_input` (there is no `unsupported_mode` code).
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
`signed_receipt` is a string; absent or `null` is the verdict `malformed` (the one member whose absence is a verdict), any other type is `invalid_input`. `keys` and `policy` are typed as described under Input strictness.
Output:
```json
{ "valid": <bool>, "reason": "<ReasonCode>" }
```

**Verification algorithm (MUST follow exactly; first failing check wins, in THIS order):**
1. `malformed`: any of the following, checked in this order.
   - The JWS is not exactly three `.`-separated segments.
   - A segment is not strict unpadded base64url: alphabet `A-Za-z0-9-_` only (so no `=`, `+`, `/`, space, CR or LF), length not 1 mod 4, and every trailing bit zero (one canonical encoding per byte string).
   - The header bytes are not strict JSON text that is exactly one object. Strict text means valid UTF-8 (no overlong forms, no encoded surrogates), no leading BOM (`EF BB BF`), no lone-surrogate `\uXXXX` escape in any key or string (a valid surrogate pair escape is fine), one value with nothing after it, and JSON nesting depth at most 128 (the top-level object is depth 1). Duplicate header keys are last-wins and a non-finite number in an ignored header member is accepted.
   - The header has a `b64` member that is not boolean `true` (`false` and every non-boolean value, `null` included, are malformed; `true` is the same as absent).
   - The payload bytes are not strict JSON text that is exactly one object, by the same rules. A duplicate payload key or a non-finite payload number is not decided here: it is last-wins at parse (or deferred) and fails step 7 as `non_canonical_payload`.
2. `header_key_material` — header contains ANY of `jwk`, `jku`, `x5u`, `x5c`, `x5t`, `x5t#S256` (key material MUST come from the registry, never the token — §12).
3. Resolve key: read `performer_id` from the **payload**, `kid` from the **header**. If `performer_id`/`kid` absent or not in `keys` → `unknown_key`. Lookup answers only for keys the registry contains: a `performer_id` or `kid` such as `__proto__`, `constructor` or `toString` is just a name, absent unless the registry has that exact key.
4. `revoked_key` — resolved key has `status:"revoked"`.
5. `alg_not_allowed`: header `alg` is `none`/absent, OR header `alg` != the resolved key's `alg` (no alg-substitution; `none` always rejected), OR the resolved key's `alg` is not a row of the algorithm table, OR its `kty`/`crv` are not the ones that row requires (the key-type binding rule). The table is exactly `EdDSA` requires `kty=OKP`, `crv=Ed25519`, and `ES256` requires `kty=EC`, `crv=P-256`; a missing or `null` `kty`/`crv` fails. This runs after step 4 (a revoked key stays `revoked_key`) and after the header/registry `alg` equality check.
6. `bad_signature`: the key material is unusable, or the signature does not verify under the resolved key over `b64url(header).b64url(payload)`. Registry `x` (and `y` for EC) go through the same strict base64url decoder as the JWS segments and must decode to exactly 32 bytes; padding, the standard alphabet, whitespace or a newline, non-zero trailing bits, a wrong length, or a point not on the curve is `bad_signature` (a key is never repaired). The same decoder failing on a JWS segment is `malformed` (step 1): the call site, not the decoder, picks the code. ES256 signature is raw R||S, 64 bytes, per JWS; a high-S signature is accepted. Ed25519 is cofactorless (`[S]B == R + [k]A`), compares R by its 32-byte encoding, rejects `S >= L`, and adds no small-order or identity-key rejection: A is accepted if it decodes with `y` reduced mod p (and `x=0` with the sign bit set accepted).
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
- A vector pins its stdin in EXACTLY ONE of three forms; a vector with none or several is a bad vector:
  - `input`: structured JSON, serialized by the harness.
  - `input_raw`: the exact stdin text, verbatim (duplicate keys, escape text such as `\ud800` as six ASCII characters).
  - `input_raw_b64`: standard base64 of the exact stdin BYTES, for what a JSON string cannot carry (invalid UTF-8, a BOM followed by text, NUL). The harness, the Go CLI test and the TS test decode it to bytes and pipe them unmodified.
  A present-but-empty `input_raw` or `input_raw_b64` is EMPTY stdin, never "absent".
- `profiles` is the atoms the vector needs (see Profiles above). It sits right after `command`, is computed by the generator, and the harness rejects a vector without it, with an unknown atom, or with a stored `cmd:` atom.
- The harness captures stdout as bytes and compares bytes. Output that is not strict UTF-8 fails the vector (`NON-UTF8-OUTPUT`) instead of being repaired to U+FFFD.
- An `error` anchor means a command error for EVERY command, `verify` and `verify-chain` included; a verdict anchor means a `{valid:false}` result.
- `anchor` is OPTIONAL. When present it is an externally-known-correct expected output (e.g. an RFC 8785 test value or a hand-computed digest). The harness asserts EVERY answering implementation matches the anchor AND each other.
- When `anchor` is absent, the harness asserts only that at least two implementations answer and agree with each other (catches ambiguity; does not catch both-wrong-the-same-way, which is what anchors are for).

## Harness output
`conformance/compare.mjs` prints the registered implementations (`impls: go ts`), a coverage matrix (answered over total per vector group and implementation), one line per failure naming the vector or atom, `vectors: N`, and `N/N passed.`. Failure kinds include `DIVERGE` (two answering implementations disagree), `ANCHOR-FAIL`, `NOANCHOR` (an error output with no anchor), `SILENT-ANSWER`, `EMPTY-OUTPUT`, `BADDECLINE`, `NONUNIFORM`, `ORPHAN` (no implementation answered), `DEAD-PROFILE`, `FLOOR-BREACH`, `IMPL-MISSING` and `IMPL-UNSPAWNABLE`. Exit 0 only when there is no failure line; otherwise exit 1.

Implementations come from the environment: `GO_VERIFY` and `TS_VERIFY` (defaults `./bin/vitni-verify-go` and `node ts/dist/cli.js`), and `PY_VERIFY` for the optional Python verifier. When `PY_VERIFY` is set but the process cannot be spawned the run fails; it is never skipped.
