# Vitni — Protocol Design Draft 0.2
### Performer-co-signed execution receipts for MCP tool calls and A2A tasks

**Status:** ROUGH DRAFT — for understanding, not implementation.
**Date:** 2026-05-28
**Scope of this document:** the *functionality and logic* of Vitni — objects, bytes, flows, algorithms, failure modes. **No market/GTM content** (that lives in the research report §10).

> **Changelog 0.1 → 0.2:** hardened by a 5-lens adversarial review. The §0.1 normative claim "two verifiers produce byte-identical verdicts" did **not** hold — several byte-source definitions were underspecified. 0.2 pins them: multibase hash-string encoding, the SSE/streaming decode unit, the JWS-payload≡JCS invariant, the inputs-vs-outputs hashing split, JOSE alg/kid hardening, cost-as-strings (JCS integer ceiling), and corrects a factual AP2 error. Also closes a value-cap breach (§9 reason codes) and five missing threat rows (§16).

---

## 0. What Vitni is and is not (the hard boundary)

Vitni produces a **signed, tamper-evident, content-addressed record of an action, signed by the party that performed it.** That is the entire claim. Every design decision below serves that and refuses to serve anything else.

**Vitni proves (the value cap):**
- **Performer non-repudiation** — the performer cannot later deny it returned *these* output bytes, at *this* time, against *this* request, for *this* cost.
- **Response-byte integrity** — the recorded output cannot be altered after signing without detection.
- **Authorization binding (by hash)** — the receipt records *which* authorization token the performer **claims** was on the wire (it does not, and cannot, prove the performer hashed the token it actually used — see §6, §16).
- **Verifiable cost attribution** — the performer-signed cost fields sum over a *fully-verified* chain (§7) into a ledger the performer cannot later understate.

**Vitni does NOT prove (and v1 must never claim):**
- ❌ That the action was *correct*, *truthful*, or *non-hallucinated*. A signed receipt of a wrong answer is still a valid receipt of a wrong answer.
- ❌ That a **world side-effect** happened (card actually charged, email actually delivered). It proves the performer *returned bytes claiming so*; downstream-system proof requires the downstream system to be the signer (out of scope v1).
- ❌ **Intent integrity.** A prompt-injected-but-authorized request produces a perfectly valid receipt. Vitni signs *what was executed*, never *whether it should have been*.
- ❌ **Authorization enforcement.** Vitni binds to the token by hash for *audit*; it does not validate the token, check its scope, or refuse out-of-scope calls. That is a capability-token layer's job.

**These boundaries are normative.** A conformant implementation that markets beyond them is non-conformant. Where a later section names a code or field that *looks* like it crosses this line (e.g. `MANDATE_EXCEEDED`, `INTENT_MISMATCH` in §9), it is explicitly marked **performer-self-reported** and asserts nothing Vitni verifies.

---

## 0.5 Related work and differentiation

The 2026 agent-receipt field is crowded, but it clusters on one side of the action:

- **AP2 Payment Mandates** — W3C Verifiable Credentials (JSON-LD / Data Integrity), signed **ECDSA P-256 + SHA-256**; the Checkout JWT path explicitly requires a **non-deterministic** signature (so Ed25519 is disallowed there). Covers *authorization-and-intent before payment*.
- **ASQAV / ACTA / agent-delegation-receipts (IETF 2026 drafts)** — sign the *authorization / delegation / decision* side; commit to grants, not to execution output.
- **Signet** — agent-signs-request / server-signs-response, JCS, MCP `_meta`, offline-verifiable. Closest prior art; Vitni deliberately keeps **only** the performer-signs-response half (we amputated the requester-signs half — §1).

**The thesis:** every shipping protocol signs the **authorization / decision / payment** side. **None commit to execution OUTPUT bytes + performer cost.** Vitni is the complementary half. **Intentional divergences** (must be stated, not silent): multihash-with-pinned-multibase instead of raw-hex SHA-256 (algorithm agility); in-band `_meta` instead of a side-channel log; and **decode-then-hash streaming commitment (§4.3), which is genuinely un-taken prior art** and the riskiest novel part. Vitni must *ingest* AP2/Signet receipts (via `rail_ref` / `parent_receipt_hash`), never re-implement them.

---

## 1. Roles and terminology

| Role | Definition |
|------|-----------|
| **Requester** | The agent that *invokes* a tool/skill. Does **not** sign the receipt. (We amputated the self-signed requester model — it proves only a claim by the suspect.) |
| **Performer** | The MCP tool **server** or A2A skill **provider** that *executes* the action. **The sole signer of the receipt.** |
| **Verifier** | Any party that validates a receipt: the requester, an auditor, a FinOps tool, a downstream performer in a chain. |
| **Witness / Log** | The optional Certificate-Transparency-style append-only log that records receipt hashes and issues inclusion proofs. May be operated by a third party; may have external co-witnesses. |
| **Receipt** | The signed object. The atomic unit. |
| **Chain / DAG** | A set of receipts linked by `parent_receipt_hash` representing a multi-hop execution. |

**Trust model (v1):** the Verifier already knows or can fetch the Performer's public key (via the Performer's published AgentCard Vitni key field or MCP server metadata — §10). Cross-stranger / internet-scale identity is **out of scope for v1** (depends on unsettled WIMSE/SCIM-for-agents).

---

## 2. The Receipt object

The canonical logical structure (encoding rules in §3–4).

```
Receipt {
  v:               "vitni/0.2"            // spec version (string, required)
  binding:         "mcp" | "a2a" | "local"  // execution context discriminator (required, signed) — §13/§14/§15
  action_ref:      <hashstr> | null         // multihash of the auth token the performer CLAIMS was used (§6); null if none
  performer_id:    <string>                // stable identifier of the performer; resolves to a key (§10)
  requester_id:    <string> | null         // identifier of the invoking agent, as known to the performer (ADVISORY; not verifiable in v1)
  method:          <string>                // namespaced by binding: "mcp:<tool>" | "a2a:<skill>" | "local:<tool>"  (§13/§14/§15)
  inputs_hash:     <hashstr>                // commitment to the request (§4.2, §5) — JCS(params) for MCP inputs
  outputs_hash:    <hashstr>                // commitment to the response payload (§4.2–4.3, §5)
  cost: {                                   // performer-attested cost (§8); all fields required
    tokens:        "<decimal-string>"       // model tokens (STRING-encoded integer — §4.1 number rule)
    usd_micros:    "<decimal-string>"       // millionths of a USD (STRING-encoded integer; no floats, ever)
    wall_ms:       "<decimal-string>"       // wall-clock ms (STRING-encoded integer)
    rail_ref:      <string> | null          // external settlement reference (x402 txid, AP2/card auth id) if a payment occurred
  }
  status:          <StatusCode>            // outcome (§9)
  reason:          <ReasonCode> | null      // REQUIRED when status != OK, else null (§9)
  parent_receipt_hash: <hashstr> | null     // the receipt_id of the action that CAUSED this one (§7); null at chain root
  parent_performer_id: <string> | null      // OPTIONAL (signed): the performer_id the child EXPECTS its parent to have — binds lineage identity, defeats foreign-parent splice (§7, §16). "Carried" = present and non-null; an empty string is carried (and, being unequal to any real performer_id, forces parent_identity_mismatch). Only absence or explicit null means "no claim".
  log_policy:      "logged_required" | "best_effort"   // performer's logging commitment (signed) — §11
  ts:              <rfc3339-utc>           // performer's claimed signing time (advisory; the Log is the time-of-record authority)
  nonce:           <hashstr>                // >= 128 bits from a CSPRNG (§2.1); uniqueness + anti-grinding
  ext:             { ... } | absent         // OPTIONAL namespaced extensions; never affects core verification
}
```

`receipt_id` is **NOT a field of the Receipt.** It is *derived*: `receipt_id = multibase( multihash( JCS(Receipt) ) )` (§4.1). A child carries its parent's derived `receipt_id` by value in `parent_receipt_hash`. Excluding `receipt_id` from the signed body is what makes the derivation non-circular.

Signed form:
```
SignedReceipt = JWS(performer_key, payload = JCS(Receipt))      // §3, §4.1
```

*Decision noted: cost magnitudes are STRING-encoded integers, not JSON numbers — RFC 8785/JCS serializes numbers via ECMAScript rules and loses precision above 2^53-1; §8 summation pushes values large; strings sidestep all cross-language number divergence. Reversal cost: medium (changes the signed shape). **Empirically confirmed by the conformance harness:** a JSON integer `9007199254740993` (2^53+1) is silently rounded to `9007199254740992` by BOTH the Go and TS verifiers — identical corruption, no divergence to detect. For money, that silent rounding is the whole danger; string-encoding eliminates the JSON-number path entirely.*
*Decision noted: multihash-prefixed hashes + ONE pinned multibase (§4.1) — algorithm agility without a format break, and a single deterministic string form so two verifiers compute identical signed bytes. Reversal cost: low.*
*Decision noted: explicit `binding` discriminator + binding-namespaced `method` — without it an MCP receipt can be lifted and presented as an A2A receipt, or "refund" replayed where "charge" was expected (§16). Reversal cost: low.*

### 2.1 Field rationale (the non-obvious ones)
- **`receipt_id` is derived, not assigned** (above) — impossible to forge an id; two verifiers always compute the same id; this is what makes receipts content-addressable and chainable.
- **`nonce` MUST be ≥128 bits from a CSPRNG.** It guarantees `receipt_id` uniqueness for genuinely-identical actions *and* prevents `receipt_id` grinding. It is **not** a replay defense on its own (see §16 — replay defense comes from verifier request-binding + Log ordering).
- **`action_ref` is a hash, not the token** — never embed a bearer credential in an audit artifact. It commits to *which* token the performer claims it used, without carrying it (§6).
- **`parent_receipt_hash` points at the *cause*, not the *child*** — a receipt is written *after* its action, so it can only reference what already happened. The DAG is built bottom-up and is immutable (§7).

---

## 3. Cryptographic envelope

The Receipt is **always JSON**, signed as a **JWS** (RFC 7515).

| Profile | Envelope | Use |
|---------|----------|-----|
| **JSON profile** | **JWS** (RFC 7515) over `JCS(Receipt)` | **v1 — the only mandatory profile.** |
| **Binary profile** | **COSE** (RFC 9052) `COSE_Sign1` over dCBOR | **DEFERRED (post-v1).** |

**RESOLVED (Q1): JWS-only v1.** Most tool I/O is JSON; mandating COSE now would double the conformance-vector surface before byte-exact verification is proven even once.

**JWS constraints (normative, v1):**
- The JWS **payload MUST be exactly the `JCS(Receipt)` octets** (§4.1). Compact serialization. **RFC 7797 unencoded-payload (`b64:false`) and detached payloads are FORBIDDEN** in v1.
- Verifier MUST base64url-**decode** the payload, parse it, **re-run JCS, and assert byte-equality** with the decoded payload (reject a non-canonical payload even if the JWS signature is otherwise valid). `receipt_id` is computed over those decoded JCS octets.

**Signature algorithms (v1 mandatory-to-implement):**
- **EdDSA / Ed25519** — preferred for general execution receipts (deterministic, fast, small, no nonce-reuse footgun).
- **ECDSA / P-256 (ES256)** — required: it is the dominant algorithm across FIDO/WebAuthn, enterprise PKI, and W3C VC tooling, and is what most agent-identity infrastructure already issues. *Note: AP2's Checkout-JWT path mandates a non-deterministic signature and therefore forbids Ed25519 — a performer emitting Vitni receipts on that path MUST use ES256. The "Ed25519 preferred" default applies to ordinary execution receipts, not the AP2 checkout leg.*

---

## 4. Canonicalization — the make-or-break layer

This is where receipt protocols die (XML-DSig, JSON-LD). **The slogan "hash-of-bytes sidesteps canonicalization" is false** — it only moves the decision to *where the bytes are defined*. We define every byte source explicitly.

### 4.1 The Receipt envelope and the hash-string encoding
- Canonicalized with **RFC 8785 JCS** over a **strict I-JSON subset** (RFC 7493): UTF-8, no duplicate keys, sorted keys, **no JSON numbers in the core at all** (every integer magnitude is a decimal string — see §2 `cost`), no insignificant whitespace.
- **Hash-string encoding (pinned):** every hash-valued field (`action_ref`, `inputs_hash`, `outputs_hash`, `parent_receipt_hash`, `nonce`, and the derived `receipt_id`) is a **multihash** serialized as **multibase `base64url` (no padding), prefix `u`**. Exactly one encoding is legal in the core; alternates may return only under a future profile flag. *Rationale: JCS preserves string values verbatim (RFC 8785 §3.1 — no normalization), so an unpinned encoding (base32 vs base64url vs upper/lower hex) makes two correct implementations produce different signed bytes for the same logical receipt.*
- **Unicode:** Vitni performs **no** Unicode normalization (consistent with JCS). String fields commit to the exact code points received. Producers SHOULD emit identifiers in **NFC**. (JCS yields byte-identical output only for strings that are already byte-equivalent after JSON escaping — it is not a semantic normalizer.)
- `receipt_id = "u" + base64url( multihash( JCS(Receipt) ) )`, where `Receipt` excludes `receipt_id` itself (§2).

### 4.2 Payloads — the hashing rule, split by DIRECTION
"Hash the wire octets" is only implementable in one direction. We split it:

- **OUTPUTS (`outputs_hash`):** the performer hashes **the exact octet sequence it emits on the transport** (it controls those bytes). For MCP, see §13 for *which* octets. For streaming, see §4.3.
- **INPUTS (`inputs_hash`):** the performer **does not receive raw request octets** — the JSON-RPC / A2A layer parses `params` before the handler runs, so there are no original wire octets to hash. Therefore `inputs_hash = multihash( JCS(params) )` (re-canonicalize the parsed inputs). *This is the one place we deliberately accept re-canonicalization, because the alternative (hash-of-received-octets) is not implementable for inputs.* High-precision numeric arguments MUST be string-encoded by the caller or they are subject to the §4.1 number rule.

### 4.3 The streaming commitment unit (decode-then-hash, fully specified)
Streaming/chunked responses have no single "the bytes" *as framed*, so v1 commits to the **decoded application-level content**, defined to the byte:

**For Server-Sent Events (A2A SSE, MCP streamable-HTTP SSE):** parse per WHATWG SSE (html.spec.whatwg.org §9.2), then commit to:
- the **UTF-8 ordered concatenation of application message payloads**, where one *message* = the WHATWG-parsed `data` buffer (multiple `data:` lines joined by `U+000A`, **trailing `U+000A` stripped**);
- **exclude:** a leading UTF-8 BOM, comment lines (`:`…), and `event:` / `id:` / `retry:` fields (these are framing, not content);
- **normalize line terminators** (`CRLF`, lone `CR`, lone `LF`) per the SSE parser before extracting `data`;
- **join successive messages with a single `U+000A` separator** (messages are length-implicit via this separator; an empty trailing message is dropped).
- For **JSON-RPC-over-SSE** (MCP), the committed bytes are the **inner `result` value's wire octets**, not the SSE frame nor the JSON-RPC envelope. A message with **no `result` key is skipped**; a message with a **present `result` of JSON `null` IS included** (committing to the bytes `null`). *(Pinned after the conformance harness confirmed both the Go and TS verifiers agree on this interpretation — §0.1 of the harness.)*

`outputs_hash = multihash( committed_bytes )`. **Robust to re-chunking and re-framing:** a proxy that re-frames the stream changes framing, not the decoded content, so the hash is stable.

**Accepted cost (stated honestly):** **not incrementally verifiable** — the verifier MUST buffer the full response before computing `outputs_hash`. Bounded by response size; URI-large content is scoped out (§4.4). Incremental verification, if ever needed, returns as an additive mode under a profile flag, never by weakening this default.

*Decision noted (Q2): decode-then-hash the WHATWG-parsed message content, framing discarded — robustness to proxy re-chunking over incremental verification. This is novel prior art and the highest-risk part; it MUST be proven with the §16.1 streaming conformance vectors. Reversal cost: medium.*

### 4.4 URI-referenced parts are scoped OUT
If a result references content by URI, the receipt records `{uri, declared_digest}` (the digest as a pinned-multibase hash string), **not** the dereferenced remote bytes (remote content can change, is off the hot path, and reintroduces a fetch dependency into verification). Verifying remote bytes match `declared_digest` is a *separate, optional* verifier step.

---

## 5. The hashing / commitment model (summary)

| What | Commitment |
|------|-----------|
| Receipt envelope | `JWS` over `JCS(Receipt)`; `receipt_id = "u"+base64url(multihash(JCS(Receipt)))` |
| MCP **inputs** | `multihash( JCS(params) )` — re-canonicalized (no wire octets exist), §4.2 |
| **Outputs** (non-stream JSON) | `multihash` of the emitted result octets, §13 picks which |
| **Outputs** (binary, inline) | `multihash` of the exact emitted octets |
| **Outputs** (streamed) | `multihash` of the WHATWG-decoded, reassembled message content, §4.3 |
| URI-referenced content | `{uri, declared_digest}`; remote bytes NOT fetched at verify time |
| Authorization token | `action_ref = multihash` of the token octets the performer **claims** it used (§6) |
| **Inputs** (local) | `multihash` of raw input octets as read — no re-canonicalization (performer sees raw bytes) |
| **Outputs** (local) | `multihash(JCS(output object minus receipt key))` — formatting-independent, receipt cycle broken |

All hash strings: multibase `base64url`-nopad, prefix `u` (§4.1).

---

## 6. Authorization binding (binding, not enforcement)

When the inbound request carried an authorization token (AIP / Agentic-JWT / AP2 mandate / OAuth), the performer records `action_ref = multihash( token_octets )` over **the exact octets it received** — Vitni does **NOT** canonicalize the token. *Consequence: a JSON-LD/VC token (e.g. an AP2 mandate) with no stable serialization may not round-trip; an auditor MUST present the byte-identical token to re-derive `action_ref`.*

**What this proves:** an auditor holding the receipt and a byte-identical token can show, offline, that *this execution referenced that exact token*. Combined with a fully-verified chain (§7), it shows authorization lineage.

**What this explicitly does NOT do:** Vitni does **not** parse, validate, scope-check, or enforce the token (binding ≠ enforcement — that's a Biscuit/macaroon layer). **Nor does it prove the performer hashed the token it actually used** — a lying performer can record `action_ref = hash(innocuous T1)` while executing against broad `T2` (§16, *action_ref substitution*). Hence §0 says "claims," not "proves."

**Graft from Caveat (optional `ext`, advisory):** the performer MAY record the token's declared scope in `ext.caveats` for an after-the-fact bounds check — advisory only; the performer is self-reporting the scope it saw.

---

## 7. The receipt chain / DAG

Multi-hop execution (Requester → Orchestrator → Specialist → Tool) produces a **DAG of receipts linked child→parent**:

```
        [R_tool: leaf, parent_receipt_hash = receipt_id(R_specialist)]
                          │
        [R_specialist: parent_receipt_hash = receipt_id(R_orchestrator)]
                          │
        [R_orchestrator: parent_receipt_hash = null  (chain root)]
```

- Each receipt sets `parent_receipt_hash = receipt_id` of the receipt for the action **that caused it**.
- **Immutable & append-only by construction:** a receipt commits to its parent's content hash, so altering any ancestor invalidates every descendant's linkage.
- **Fan-out** (one orchestrator calls 3 tools) → 3 receipts sharing one `parent_receipt_hash` — a tree, hence DAG.
- **Full-chain verification is MANDATORY for any cost-aggregation (§8) or authorization-lineage (§6) claim** — leaf-only verification does **not** validate lineage and is vulnerable to chain-splicing (§16). Full-chain verification (1) per-receipt verifies every hop (§12 steps 1–8) under each hop's own performer key, (2) checks `child.parent_receipt_hash == receipt_id(parent)` for every link, (3) requires the root hop's `parent_receipt_hash == null` and every non-root hop's `parent_receipt_hash != null`, and (4) when a hop carries `parent_performer_id`, requires it to equal the provided parent's `performer_id` (closes the foreign-parent splice — a validly-signed receipt from the *wrong* performer cannot be re-parented in).
- **Residual (honest):** without `parent_performer_id`, a validly-signed receipt from any performer can be spliced as a parent (structural checks pass). The optional field is the defense; chains that omit it get structural integrity only, not lineage-identity binding.

**What the chain proves:** "this leaf occurred within this lineage of caused-by relationships, each step signed by its performer." **Not** that the orchestrator faithfully represented the parent's intent to the child (intent integrity — out of scope).

---

## 8. Cost accounting

`cost{}` is **performer-attested** (the performer knows its true token/dollar/time cost; the requester cannot). All magnitudes are string-encoded integers (§4.1).

- **Per-chain total** = sum of `cost` over all receipts in a **fully-verified** DAG (§7) rooted at a given receipt.
- **Per-principal** = sum over chains whose **root receipt has a non-null `action_ref`** tracing to a principal's grant. *Null-`action_ref` chains are attributable per-agent only, NOT per-principal* (consistent with §2/§6 nullability).
- **Per-agent** = sum over receipts with a given `performer_id` (or, advisory only, `requester_id`).
- **Large sums:** aggregation is performed on the decoded integers (arbitrary-precision); a serialized aggregate is emitted as a decimal string, never a JSON number.

**"Un-gameable" — the precise limit:** the performer cannot *later* understate a cost it already signed (non-repudiation). It is **NOT** prevented from signing a *false* cost at emission — but systematic divergence from the rail/invoice of record creates durable, attributable evidence against it. **Tamper-evident and non-repudiable, not omniscient.** `rail_ref` cross-references an external settlement (x402 txid, AP2/card auth).

---

## 9. Status and reason taxonomy

```
StatusCode (enum, required):
  OK | PARTIAL | FAILED | REJECTED

ReasonCode (closed core enum; REQUIRED when status != OK, else null):
  // cryptographically-grounded / execution outcomes
  TIMEOUT  RATE_LIMITED  UPSTREAM_ERROR  INVALID_INPUT  INTERNAL_ERROR
  DELIVERY_FAIL  PAYMENT_DECLINED  PAYMENT_REVERSED
  // PERFORMER-SELF-REPORTED judgments (see boundary note below)
  MANDATE_EXCEEDED  MANDATE_EXPIRED  INTENT_MISMATCH
```

The enum is **closed in the core** so dispute tooling can switch deterministically; vendor-specific reasons go in `ext`, never in `reason`.

> **Value-cap boundary note (normative).** `MANDATE_EXCEEDED`, `MANDATE_EXPIRED`, and `INTENT_MISMATCH` are **performer-self-reported** — they require the performer to have parsed and judged the token/intent, which §0 and §6 say Vitni does **not** verify or enforce. They have the same status as `ext.caveats`: a Vitni receipt carrying one asserts **nothing Vitni verifies**, and their **absence proves nothing** about scope or intent. A dispute tool MUST NOT treat them as cryptographic evidence of authorization or intent adjudication. (They remain in the enum for deterministic switching, fenced by this note.)

*Decision noted: keep MANDATE_*/INTENT_MISMATCH in the closed enum but fence them as self-reported — moving them to `ext` loses deterministic switching for dispute tooling; the normative fence preserves the §0 value cap without sacrificing it. Reversal cost: low.*

---

## 10. Key discovery / PKI (v1 = known-counterparty)

The performer's signing key MUST be discoverable through a channel the performer already operates:

- **A2A:** publish Vitni verification key(s) in a **dedicated Vitni field in the AgentCard**. *Correction (0.2): A2A's AgentCard `signatures` field signs the card itself — A2A does NOT define a published JWKS/verification-key set for third-party object verification. So Vitni defines its own key location in the AgentCard (symmetric to MCP's `vitni_keys`), reusing only the JWS/JCS crypto primitives, not a non-existent publishing channel.*
- **MCP:** publish key(s) in **MCP server metadata** (`vitni_keys` in the server's advertised metadata / `.well-known`).

**Key rotation:** keys carry a `kid`; receipts reference `kid` in the JWS header; performers publish current + recent-past keys so in-flight receipts verify across a rotation. **The verification algorithm and curve are selected from the resolved key's published metadata (`kid → key → alg`), never from the JWS header** (§12).

**Revocation [short-lived keys + Log freshness anchor]:** v1 = short-lived published key sets + the Log as freshness anchor (a `receipt_id` logged under an STH *before* a key's revocation timestamp is valid-as-of-witnessing; one logged after is rejected). Full CRL/OCSP/StatusList **deferred and flagged as a known gap.** **Honest residual (0.2):** within a stolen key's validity window the attacker can log a forged receipt *before* the revocation STH and it stays valid forever (STH timestamps are monotonic; the Log cannot retroactively exclude it); **L1 (offline) verifiers get no revocation at all.** Mitigation: minimal key lifetimes; verifiers SHOULD treat receipts near a revocation boundary with suspicion. **This is the weakest link (§16).**

**Cross-stranger (no prior relationship): out of scope v1** (depends on WIMSE/SCIM-for-agents/DIDs, unsettled in 2026). v2 layer.

---

## 11. The transparency log (CT-style)

A receipt is non-repudiable on its own. The Log adds **defense against backdating and equivocation**.

- **Structure:** append-only Merkle tree of `receipt_id`s, **RFC 6962-style with domain-separated hashing** (`0x00` leaf / `0x01` node prefixes). Periodic **Signed Tree Head (STH)**.
- **Inclusion proof:** Merkle audit path proving a `receipt_id` is in the log as of an STH.
- **Witnessing:** STH MAY be co-signed by **external witnesses** so the operator cannot rewrite history alone.
- **Optional tier:** receipts are **fully valid offline (L1)**; the Log is an **opt-in upgrade (L2)**. **L1** = signature + integrity + binding + cost. **L2** = L1 + inclusion proof + revocation freshness. A verifier states which level it checked (§12 step 9).
- **Downgrade defense (0.2):** the signed `log_policy` field expresses the performer's commitment. `log_policy = "logged_required"` ⇒ a verifier **MUST** obtain an inclusion proof or **reject** (no silent L1 fallback). Verifiers MAY set a local minimum-level policy. Without this, a malicious presenter withholds the proof and silently forces L2→L1, discarding equivocation + revocation defenses (§16).

*(Full Log wire-format — STH signature scheme, tree-hash algorithm, cross-impl inclusion-proof vectors — is specified when L2 is built; L2 is opt-in, not a v1 baseline blocker.)*

---

## 12. Verification algorithm

Given a `SignedReceipt` R, optionally a transport-observed payload, optionally a token, optionally an STH, and a local minimum-level + expected `(binding, method)` policy:

```
1.  PARSE        decode the JWS; reject if malformed; reject RFC 7797 b64:false / detached payloads.
2.  KEY+ALG      resolve performer_id + header.kid -> published key (§10).
                 Take alg/curve FROM the resolved key's metadata, NOT the header.
                 Reject: 'none'; any jwk/jku/x5u/x5c/x5t header; header.alg vs key-type mismatch;
                 unknown/expired-without-rotation-coverage key.
3.  SIGNATURE    verify JWS signature over the transmitted payload with the resolved key; reject on failure.
4.  CANON        base64url-decode payload; parse; re-run JCS; assert byte-equality (reject non-canonical).
5.  RECEIPT_ID   receipt_id = "u"+base64url(multihash(decoded-JCS bytes)); (no stored field to compare — it is derived).
6.  CONTEXT      assert R.binding and R.method match the expected (binding, method) policy; reject mismatch.
7.  PAYLOAD      (optional) recompute inputs_hash = multihash(JCS(params)) and/or
                 outputs_hash per §4.2-4.3 (streaming: buffer + WHATWG-decode + reassemble); reject on mismatch.
8.  AUTH         (optional, if token held) recompute multihash(token octets); reject if != action_ref.
9.  CHAIN        (MANDATORY if cost-aggregation or auth-lineage is claimed; else optional)
                 verify parent_receipt_hash == receipt_id(parent); verify parent signature under parent's key;
                 check expected parent performer_id; recurse 1-8 on each ancestor.
10. LOG          if R.log_policy == "logged_required" OR local policy requires L2:
                 verify inclusion proof of receipt_id against STH; check key freshness as-of-STH; else reject.
11. VERDICT      emit { valid, level: "L1"|"L2", checks_performed, self_reported_fields, caveats }.
```

**Normative requirement:** two independent conformant verifiers MUST produce **byte-identical** verdicts and identical recomputed hashes on every conformance vector (§16.1). This is the property the whole protocol's credibility rests on — and the reason §3/§4 pin every byte source.

---

## 13. MCP binding

- A receipt rides in the MCP **tool-call result** under a **reverse-DNS `_meta` key: `dev.vitni/receipt`** (single-label and `mcp`/`modelcontextprotocol` second-labels are reserved; reverse-DNS avoids collision). Pin to a targeted MCP spec version in the conformance suite.
- **Rationale (corrected 0.2):** `_meta` is the sanctioned, forward-compatible Result-extension namespace. It is **not** an `outputSchema` workaround — `outputSchema` validates only `structuredContent`, so a sibling field would not be rejected anyway. (Shipping the old false rationale would invite an implementer to move the receipt top-level, which *would* then collide.)
- **`inputs_hash`** = `multihash(JCS(params))` (§4.2 — the server gets parsed params, not octets).
- **`outputs_hash`** (pinned): `multihash` over `JCS(result object excluding _meta)` — this naturally excludes the embedded receipt and resolves the content-vs-structuredContent ambiguity (MCP structured tools SHOULD return the data in both; hashing the whole result-minus-`_meta` covers both deterministically).
- Zero new transport, zero extra round-trip; a client that doesn't understand `dev.vitni/receipt` ignores it (forward-compatible).

> **Empirically validated (2026-05-28) against `@modelcontextprotocol/sdk` v1.29.0** via an end-to-end demo (`ts/src/mcp/`, official `Server`/`Client` over `InMemoryTransport`):
> - The `_meta["dev.vitni/receipt"]` JWS **survives JSON-RPC serialization and the client's `CallToolResultSchema` parse intact** — the Result `_meta` schema is `$loose` (passthrough), so reverse-DNS-namespaced keys are preserved, not stripped or reordered.
> - **`outputSchema` validation is orthogonal:** `McpServer` validates only `result.structuredContent` against the declared schema and never inspects `_meta`. A tool may declare an `outputSchema` and still carry a receipt — co-signing is compatible with structured-output tools.
> - Cleanest injection point is the low-level `Server` + `setRequestHandler(CallToolRequestSchema, …)` (returns a plain result envelope to attach `_meta` to); wrapping `registerTool`'s callback also works.
> - The middleware MUST sign over the **JCS-canonical** payload octets, or §7 verification correctly rejects the receipt as `non_canonical_payload`. Round-trip + tamper-rejection both confirmed.

---

## 14. A2A binding

- A receipt is attached to the A2A **Task artifact** on completion. `binding = "a2a"`, `method = "a2a:<skill-id>"`.
- **Artifact canonicalization (we define it — A2A doesn't):** A2A `Part` is a union — map each variant onto §4:
  - `TextPart`, `DataPart`, inline `FilePart` (bytes) → hash inline content per §4.2/§4.3;
  - `FilePart` by URI → record `{uri, declared_digest}` per §4.4.
  - The **parts array** is committed via `JCS` over a canonical **descriptor list** (deterministic ordering + serialization): `text`→`{kind,text}`, `data`→`{kind,data}`, inline `file`→`{kind,"file",digest:multihash(bytes),mimeType,name}` (bytes hashed, never embedded), by-uri `file`→`{kind,"file",uri,declared_digest,mimeType,name}` (never dereferenced). `outputs_hash = multihash(JCS({parts:[descriptors]}))`. Exact rule + conformance vectors in `harness/CONTRACT.md §9`.
- Multi-hop A2A delegation populates `parent_receipt_hash`, building the DAG (§7) across agent boundaries.
- *Q5 (open default):* define artifact canonicalization Vitni-local **now** (we must), AND open a spec contribution to A2A in parallel — standards leverage (report §10.4) without blocking v1 on a committee.

> **Empirically validated (2026-05-28) against `@a2a-js/sdk` v0.3.13** via an end-to-end demo (`ts/src/a2a/`, real `AgentExecutor` + `DefaultRequestHandler` + `InMemoryTaskStore` + `ExecutionEventBus`):
> - The receipt lives at **`artifact.metadata["dev.vitni/receipt"]`** (reverse-DNS namespaced). `Artifact.metadata` is typed `{ [k: string]: unknown }` (passthrough), so the receipt **survives intact** through the handler → task-store → event-bus path; confirmed by reading `task.artifacts[0].metadata` on the consumer side.
> - `outputs_hash` is the **§9 artifact-hash over `artifact.parts` in array order**; by-URI file parts are **never dereferenced** (only `declared_digest` is bound, §4.4).
> - The hashed **descriptor (§9) is deliberately decoupled from A2A's raw `Part` schema** — a thin adapter maps SDK `Part` shapes into the descriptor, so an evolving A2A `Part` schema does not break receipt stability. Round-trip + tamper-rejection both confirmed.

---

## 15. `local` binding — non-transport actions

For actions that do not cross MCP or A2A — a local tool transforming input
bytes into an output object (e.g. a serializer, a compiler, a batch job) —
receipts use `binding: "local"` and `method: "local:<tool>"` (e.g.
`local:daimon.serialize`). Overloading `binding: "mcp"` for a non-MCP action
is exactly the cross-binding lifting the discriminator exists to defeat (§2
rationale) and is non-conformant.

Byte sources (the local hashing profile):

- **`inputs_hash`** = `multihash(raw input bytes)` — the exact octet sequence
  of the input file/stream as read, NO re-canonicalization. Unlike MCP (§13),
  a local performer sees raw octets, so §4.2's OUTPUTS rule ("hash the exact
  octets") applies to its input side too. Re-canonicalization is justified
  only when the signer never sees raw octets.
- **`outputs_hash`** = `multihash(JCS(output object with the receipt-carrying
  key removed))` — formatting-independent, so a pretty-printed local copy and
  a re-dumped mirror verify identically; excluding the receipt key breaks the
  self-reference cycle (same construction as MCP's `_meta` exclusion, §13).

The receipt itself travels wherever the output travels — as a top-level key
of the output document, in a sidecar, or both. `local` receipts carry no
transport metadata key; `dev.vitni/receipt` (§13) is MCP/A2A-specific.

---

## 16. Threat model

| Attack | Outcome |
|--------|---------|
| Tamper with a signed receipt | **Detected** (signature + receipt_id recomputation). |
| Performer denies it returned X | **Defeated** (non-repudiation). |
| **JWS alg / `none` / `kid` / `jwk`/`jku`/`x5*` header confusion** | **Defeated** by §12 step 2 (alg from resolved key, header key-material rejected, `none` rejected) — *only if* step 2 is implemented; the canonical JOSE break otherwise. |
| Non-canonical JWS payload (sign wire bytes, mismatch receipt_id) | **Defeated** by §12 step 4 (re-JCS + byte-equality). |
| Performer backdates / equivocates (two receipts, one action) | **Defeated if L2** (§11); undetected at L1. |
| **L2→L1 downgrade** (presenter withholds inclusion proof) | **Defeated only if** `log_policy="logged_required"` or local min-level=L2 (§11); silent fallback otherwise. |
| Performer signs a *false* output/cost at emission | **NOT prevented.** Tamper-evident, not truth-proving; attributable evidence against the performer. |
| **`action_ref` substitution** (hash a token not actually used) | **NOT prevented.** Same class as false cost — §0 says "claims," not "proves." |
| **Cross-binding / cross-method receipt confusion** (lift MCP receipt as A2A; replay "refund" as "charge") | **Defeated only if** the verifier pins expected `(binding, method)` (§12 step 6). |
| **`parent_receipt_hash` splicing** (dangling / foreign / unrelated-key parent) | **Defeated only by** mandatory full-chain recursion + parent signature + principal consistency (§7, §12 step 9). Leaf-only verification is vulnerable. |
| Requester is prompt-injected; emits a valid authorized malicious request | **NOT prevented.** Receipt faithfully records the malicious-but-authorized action (intent integrity — out of scope, stated loudly). |
| Requester + Performer collude on a false receipt | **NOT prevented.** Mutual collusion defeats any co-attestation; the Log limits *equivocation*, not *agreed falsehood*. |
| Stolen performer key | Forgeable within the validity window; **revocation freshness only protects receipts logged AFTER the revocation STH; the window stays valid; L1 gets no revocation. Weakest link (§10).** |
| Replay an old receipt as new | **L2:** inclusion ordering defeats replay-as-new. **L1:** NOT defeated (an old valid receipt re-verifies) — application-layer dedup + verifier request-binding required offline. `nonce` is uniqueness, not replay defense. |
| Proxy re-chunks / re-frames a stream | **Survives** — decode-then-hash commits to WHATWG-decoded content, not framing (§4.3). |
| Over-2^53 integer to manufacture verifier disagreement | **Defeated** — cost magnitudes are strings; no JSON-number path to diverge on (§4.1). |
| Hash-string encoding divergence (base32 vs base64url) | **Defeated** — single pinned multibase (§4.1). |

**Honest summary:** Vitni converts disputes from *unreconstructable* to *adjudicable* and pushes the trust boundary one hop (to the performer, who has identity and accountability). It does not manufacture trust where none exists, and it does not touch the field's deepest wound (intent integrity).

### 16.1 Conformance vectors (the artifact that makes "conformant" falsifiable)
At minimum: valid receipt; tampered receipt; `none`-alg and header-key-material attacks; non-canonical payload; multihash-string round-trip (exact string asserted); over-2^53 cost; **SSE streaming set — CRLF vs LF vs lone-CR framing, leading BOM, comment line, split `data:` lines, JSON-RPC-over-SSE inner-result — all MUST hash identically**; chain (valid lineage + spliced/dangling parent); L1 vs L2 verdicts; MCP `result`-minus-`_meta` output hashing; A2A mixed-`Part` artifact. Two *independent* verifier implementations MUST agree byte-for-byte on every vector.

---

## 17. Design questions — status

**Resolved (0.1):** Q1 JWS-only · Q2 decode-then-hash · Q3 short-lived-keys+Log · Q4 Log optional (L1/L2).
**Resolved (0.2, from review):** hash-string multibase pinned · SSE decode unit specified · JWS≡JCS invariant · inputs/outputs hashing split · JOSE hardening · cost-as-strings · AP2 corrected · `binding`+`method` discriminator · `log_policy` · §9 value-cap fence · A2A key-location defined · full-chain mandatory for aggregation.
**Still open (default applied):**
- **Q5 — A2A artifact canonicalization:** define Vitni-local now + contribute to A2A in parallel (§14).
- **Q6 — `requester_id`:** advisory string only until the v2 cross-stranger layer (§1, §10).

---

## 18. Reference implementation
1. **Receipt library** (Py + TS): build/sign/serialize a Receipt (JWS over JCS; pinned multibase; string-int cost).
2. **Co-signing middleware** (Py + TS): wrap an MCP server / A2A provider; emit `dev.vitni/receipt`. **Co-signed-only; no self-signed mode in the codebase.**
3. **Two *independent* verifiers** (different languages) — to enforce the §12 byte-identical-verdict requirement against §16.1.
4. **Conformance vector suite** (§16.1) — the falsifiability artifact.
5. **(Later) Log service** — RFC 6962-style Merkle log + STH + inclusion proofs + witness co-signing.

### 18.1 keygen (tooling)

`keygen` is key tooling, not protocol: it changes neither the receipt format
nor the wire string (`vitni/0.2`). Input `{}` generates a fresh Ed25519
keypair; input `{"seed_b64": "<b64 of a 32-byte RFC 8032 seed>"}` derives the
public key deterministically. Output encodings are deliberately asymmetric:
`jwk.x` is base64url without padding because JWK (RFC 7517/8037) mandates it,
while `private_key_b64` is standard padded base64 because that is the form
`sign` consumes — do not "fix" one to match the other. A present-but-empty
`seed_b64` is `invalid_seed`, never treated as absent, so a buggy caller
cannot silently receive a fresh key.

Every standard-base64 *input* in the tooling (`seed_b64`, `private_key_b64`,
`bytes_b64`, `raw_b64`, A2A inline `bytes`) shares one accept set: exactly
canonical padded or canonical unpadded standard-alphabet base64. Non-canonical
input — embedded newlines, excess or misplaced padding, non-zero trailing
bits — is rejected identically by both implementations (Go
`vitni.DecodeStdBase64`, TS `decodeStdBase64`), pinned by conformance
vectors. A lenient decoder that silently normalizes would let the same input
succeed on one implementation and fail on the other (§4.1's rule applied to
inputs).

---

## 19. Known gaps / roadmap
- **Revocation** beyond short-lived-keys+Log (CRL/OCSP/StatusList) — weakest link (§10).
- **Cross-stranger identity** (WIMSE/SCIM/DIDs) — the v2 root-of-trust layer.
- **COSE/binary profile** — additive post-v1 (§3).
- **Post-quantum signatures** — a known gap, material if a regulatory-audit (ASQAV-adjacent) audience is targeted; `performer_id` SHOULD then resolve to an accountable legal entity.
- **Incremental streaming verification** — additive mode only, never by weakening §4.3.

---

*Draft 0.2. The byte-source pins (§3–§4), the JOSE hardening (§12), and the value-cap fence (§9) are the substance of this revision. The remaining open items are Q5/Q6 and the L2/Log wire-format, none of which block understanding what we are building.*
