#!/usr/bin/env python3
"""Generate Vitni conformance vectors with externally-computed anchors.

Anchors come from Python's hashlib/base64 (independent of the Go and TS verifier
impls under test), so a passing anchor means both impls match a third source.
Run: uv run --no-project python vectors/_gen.py
"""
import base64
import hashlib
import json
import pathlib

OUT = pathlib.Path(__file__).parent


def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def hashstr(content: bytes) -> str:
    """pinned hash-string: 'u' + base64url_nopad(multihash(sha2-256))."""
    digest = hashlib.sha256(content).digest()
    multihash = bytes([0x12, 0x20]) + digest  # 0x12 sha2-256, 0x20 = 32-byte len
    return "u" + b64url_nopad(multihash)


def write(name_file: str, obj: dict) -> None:
    (OUT / name_file).write_text(json.dumps(obj) + "\n")


def sse_parse(raw: bytes, jsonrpc: bool) -> bytes:
    """Reference WHATWG-SSE decode per design draft §4.3 — the oracle for the anchor."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("utf-8")
    # normalize line terminators: CRLF, lone CR, lone LF
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    messages: list[str] = []
    data_buf: list[str] = []
    dispatched_has_data = False
    for line in lines:
        if line == "":  # dispatch
            if dispatched_has_data:
                messages.append("\n".join(data_buf))
            data_buf = []
            dispatched_has_data = False
            continue
        if line.startswith(":"):  # comment
            continue
        if ":" in line:
            field, _, value = line.partition(":")
            if value.startswith(" "):
                value = value[1:]
        else:
            field, value = line, ""
        if field == "data":
            data_buf.append(value)
            dispatched_has_data = True
        # event/id/retry ignored
    # trailing event without blank line is NOT dispatched (per spec)
    if jsonrpc:
        parts = []
        for m in messages:
            try:
                obj = json.loads(m)
            except json.JSONDecodeError:
                continue
            if "result" in obj:
                parts.append(jcs(obj["result"]))
        return "\n".join(parts).encode()
    return "\n".join(messages).encode()


def jcs(value) -> str:
    """Minimal JCS for objects/arrays/strings/ints used in these vectors (anchor oracle)."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


# ---- SSE vectors ----
sse_cases = [
    ("sse-two-data-one-event", "sse/two-data-one-event", "sse",
     b"data: hello\ndata: world\n\n"),
    ("sse-reframed-equivalent", "sse/reframed-crlf-comment-event", "sse",
     b"event: msg\r\n: a comment line\r\nid: 7\r\ndata: hello\r\ndata: world\r\n\r\n"),
    ("sse-two-events", "sse/two-events", "sse",
     b"data: a\n\ndata: b\n\n"),
    ("sse-bom-no-space", "sse/bom-no-space", "sse",
     b"\xef\xbb\xbfdata:x\n\n"),
    ("sse-jsonrpc-inner-result", "sse/jsonrpc-inner-result", "sse-jsonrpc",
     b'data: {"jsonrpc":"2.0","id":1,"result":{"a":1}}\n\n'),
]
for fname, name, mode, raw in sse_cases:
    decoded = sse_parse(raw, jsonrpc=(mode == "sse-jsonrpc"))
    write(f"{fname}.json", {
        "name": name, "command": "sse-outputs-hash",
        "input": {"mode": mode, "raw_b64": base64.b64encode(raw).decode()},
        "anchor": {"decoded_hex": decoded.hex(), "outputs_hash": hashstr(decoded)},
    })

# ---- cost-canon vectors ----
cost_ok = {"tokens": "1500", "usd_micros": "10000000000", "wall_ms": "845", "rail_ref": None}
write("cost-valid.json", {
    "name": "cost/valid-string-ints", "command": "cost-canon",
    "input": {"cost": cost_ok},
    "anchor": {"canonical_hex": jcs(cost_ok).encode().hex()},
})
write("cost-number-error.json", {
    "name": "cost/number-must-error", "command": "cost-canon",
    "input": {"cost": {"tokens": 1500, "usd_micros": "10", "wall_ms": "5", "rail_ref": None}},
    "anchor": {"error": "cost_must_be_string_int"},
})

# ---- receipt-id vector (anchor computed from the JCS oracle) ----
receipt = {
    "v": "vitni/0.2", "binding": "mcp", "action_ref": None,
    "performer_id": "srv-demo", "requester_id": None, "method": "mcp:echo",
    "inputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
    "outputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
    "cost": {"tokens": "10", "usd_micros": "0", "wall_ms": "3", "rail_ref": None},
    "status": "OK", "reason": None, "parent_receipt_hash": None,
    "log_policy": "best_effort", "ts": "2026-05-28T00:00:00Z",
    "nonce": "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",
}
canon = jcs(receipt).encode()
write("receipt-id-basic.json", {
    "name": "receipt-id/basic", "command": "receipt-id",
    "input": {"receipt": receipt},
    "anchor": {"canonical_hex": canon.hex(), "receipt_id": hashstr(canon)},
})

# ---- receipt-id: local binding (vitni/0.2) ----
receipt_local = dict(receipt, binding="local", method="local:daimon.serialize")
canon = jcs(receipt_local).encode()
write("receipt-id-local.json", {
    "name": "receipt-id/local-binding", "command": "receipt-id",
    "input": {"receipt": receipt_local},
    "anchor": {"canonical_hex": canon.hex(), "receipt_id": hashstr(canon)},
})

# ---- receipt-id: ext present (JCS must sort inside ext) ----
receipt_ext = dict(receipt, ext={"dev.daimon/prompt_version": "3", "dev.daimon/cost_source": "api"})
canon = jcs(receipt_ext).encode()
write("receipt-id-ext.json", {
    "name": "receipt-id/ext-object", "command": "receipt-id",
    "input": {"receipt": receipt_ext},
    "anchor": {"canonical_hex": canon.hex(), "receipt_id": hashstr(canon)},
})

# ---- divergence-hunting edge vectors (round 2) ----

# sse-jsonrpc with result:null — spec ambiguity: is a present-but-null result included or skipped?
# Anchor encodes the INTENDED semantics: a present `result` key (even null) is included; JCS(null) = "null".
# If an impl skips null, it diverges from the anchor AND the other impl — surfacing the ambiguity.
raw_null = b'data: {"jsonrpc":"2.0","id":1,"result":null}\n\n'
dec_null = sse_parse(raw_null, jsonrpc=True)  # oracle includes present null -> b"null"
write("sse-jsonrpc-null-result.json", {
    "name": "sse/jsonrpc-null-result", "command": "sse-outputs-hash",
    "input": {"mode": "sse-jsonrpc", "raw_b64": base64.b64encode(raw_null).decode()},
    "anchor": {"decoded_hex": dec_null.hex(), "outputs_hash": hashstr(dec_null)},
})

# zero dispatched events (comment-only stream) -> committed empty bytes
raw_zero = b": just a comment\n\n"
dec_zero = sse_parse(raw_zero, jsonrpc=False)
write("sse-zero-event.json", {
    "name": "sse/zero-event", "command": "sse-outputs-hash",
    "input": {"mode": "sse", "raw_b64": base64.b64encode(raw_zero).decode()},
    "anchor": {"decoded_hex": dec_zero.hex(), "outputs_hash": hashstr(dec_zero)},
})

# JCS max-safe integer (2^53-1) — Python and ECMAScript agree here, so anchor is valid
write("jcs-max-safe-int.json", {
    "name": "jcs/max-safe-int", "command": "jcs",
    "input": {"value": {"n": 9007199254740991}},
    "anchor": {"canonical_hex": jcs({"n": 9007199254740991}).encode().hex(),
               "byte_len": len(jcs({"n": 9007199254740991}).encode())},
})

# JCS over-safe integer (2^53+1) — NO anchor on purpose: Python json.dumps would be a WRONG oracle
# (it prints the exact bigint; RFC 8785 routes through IEEE-754 double). This vector is a pure
# Go-vs-TS divergence probe. DIVERGE here = the exact reason cost magnitudes are string-encoded.
write("jcs-over-safe-int.json", {
    "name": "jcs/over-safe-int-no-anchor", "command": "jcs",
    "input": {"value": {"n": 9007199254740993}},
})

print("wrote vectors:")
for p in sorted(OUT.glob("*.json")):
    print(" ", p.name)

# --- byte-source JCS + digest vectors (reproducible) ---
def _v(value):
    c = jcs(value).encode()
    return {"canonical_hex": c.hex(), "byte_len": len(c)}
write("jcs-sorted-keys.json", {"name":"jcs/sorted-keys","command":"jcs","input":{"value":{"b":1,"a":2}},"anchor":_v({"b":1,"a":2})})
write("jcs-nested.json", {"name":"jcs/nested-and-unicode","command":"jcs","input":{"value":{"z":"é","a":[3,1,2]}},"anchor":_v({"z":"é","a":[3,1,2]})})
import base64 as _b64
write("digest-hello.json", {"name":"digest/hello","command":"digest","input":{"bytes_b64":_b64.b64encode(b"hello").decode()},"anchor":{"hashstr":hashstr(b"hello")}})
write("digest-empty.json", {"name":"digest/empty","command":"digest","input":{"bytes_b64":_b64.b64encode(b"").decode()},"anchor":{"hashstr":hashstr(b"")}})

# --- negative / malformed-input vectors (§4.1 strict decode; both impls MUST reject identically) ---
# Each carries an explicit error anchor so the harness asserts the RIGHT error, not merely
# that both implementations errored. Guards the strict-decode alignment (issue #31/#35).
write("neg-digest-malformed-b64.json", {"name":"digest/malformed-base64","command":"digest","input":{"bytes_b64":"aGVsbG8=!!!@@@"},"anchor":{"error":"invalid_input"}})
write("neg-digest-base64url-rejected.json", {"name":"digest/base64url-rejected","command":"digest","input":{"bytes_b64":"aa-_"},"anchor":{"error":"invalid_input"}})
write("neg-hashstring-odd-hex.json", {"name":"hashstring/odd-length-hex","command":"hashstring","input":{"algo":"sha2-256","digest_hex":"abc"},"anchor":{"error":"invalid_input"}})
write("neg-hashstring-non-hex.json", {"name":"hashstring/non-hex","command":"hashstring","input":{"algo":"sha2-256","digest_hex":"zz"},"anchor":{"error":"invalid_input"}})
write("neg-cost-bool-magnitude.json", {"name":"cost-canon/bool-magnitude","command":"cost-canon","input":{"cost":{"tokens":True,"usd_micros":"0","wall_ms":"3","rail_ref":None}},"anchor":{"error":"cost_must_be_string_int"}})
write("neg-cost-null-magnitude.json", {"name":"cost-canon/null-magnitude","command":"cost-canon","input":{"cost":{"tokens":None,"usd_micros":"0","wall_ms":"3","rail_ref":None}},"anchor":{"error":"cost_must_be_string_int"}})
write("neg-sse-malformed-b64.json", {"name":"sse-outputs-hash/malformed-base64","command":"sse-outputs-hash","input":{"mode":"sse","raw_b64":"aa!!!garbage"},"anchor":{"error":"invalid_input"}})
write("neg-a2a-malformed-inline-b64.json", {"name":"a2a-artifact-hash/malformed-inline-base64","command":"a2a-artifact-hash","input":{"artifact":{"parts":[{"kind":"file","file":{"bytes":"aa!!!@@@"}}]}},"anchor":{"error":"invalid_input"}})

# --- duplicate-key vectors (§4.1 no-duplicate-keys; #34). input_raw pins the exact
# stdin bytes so the dup keys survive the harness's own JSON.parse. Go rejects at
# jcs.Transform for exactly these three commands (others keep-last), so TS matches. ---
write("neg-dup-jcs.json", {"name":"jcs/duplicate-key","command":"jcs",
      "input_raw":'{"value":{"a":1,"a":2}}',"anchor":{"error":"invalid_input"}})
write("neg-dup-jcs-nested.json", {"name":"jcs/duplicate-key-nested","command":"jcs",
      "input_raw":'{"value":{"outer":{"b":1,"b":2}}}',"anchor":{"error":"invalid_input"}})
write("neg-dup-receipt-id.json", {"name":"receipt-id/duplicate-key","command":"receipt-id",
      "input_raw":'{"receipt":{"v":"vitni/0.2","v":"x"}}',"anchor":{"error":"invalid_input"}})
write("neg-dup-cost-canon.json", {"name":"cost-canon/duplicate-key","command":"cost-canon",
      "input_raw":'{"cost":{"tokens":"1","tokens":"2","usd_micros":"0","wall_ms":"0","rail_ref":null}}',"anchor":{"error":"invalid_input"}})

# --- sign negative vectors (#34): unknown top-level key and non-string cost are
# rejected at sign (§2 / §4.1). Full receipt supplied; both impls error before signing. ---
_sign_key = {"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}
_base_receipt = dict(receipt)  # the happy-path receipt built earlier (v vitni/0.2, string cost)
write("neg-sign-unknown-key.json", {"name":"sign/unknown-top-level-key","command":"sign",
      "input":{"receipt":dict(_base_receipt, FOO="x"), **_sign_key},"anchor":{"error":"invalid_input"}})
write("neg-sign-numeric-cost.json", {"name":"sign/numeric-cost-magnitude","command":"sign",
      "input":{"receipt":dict(_base_receipt, cost={"tokens":10,"usd_micros":"0","wall_ms":"3","rail_ref":None}),**_sign_key},
      "anchor":{"error":"invalid_input"}})
