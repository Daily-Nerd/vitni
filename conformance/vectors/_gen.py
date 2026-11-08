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


INPUT_FORMS = ("input", "input_raw", "input_raw_b64")


def write(name_file: str, obj: dict) -> None:
    """Write one vector. It pins its stdin in EXACTLY one form: `input` (structured
    JSON), `input_raw` (exact stdin text) or `input_raw_b64` (standard base64 of the
    exact stdin bytes, for what a JSON string cannot carry: invalid UTF-8, BOM)."""
    forms = [k for k in INPUT_FORMS if k in obj]
    if len(forms) != 1:
        raise ValueError(f"{name_file}: exactly one of {INPUT_FORMS} required, found {forms}")
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

# --- ES-number serialization vectors (#55). input_raw pins the exact stdin bytes:
# the harness's own JSON.stringify would round over-safe ints and reformat floats
# before the verifiers see them. Anchors are hand-pinned from RFC 8785 §3.2.2
# (ECMAScript Number::toString) — Python json.dumps would be a WRONG oracle
# (prints 10.0, -0.0, exact bigints; ES prints 10, 0, float64-rounded). ---
_num_cases = [
    ("jcs-num-float-integral", "jcs/num-float-integral", '{"value":{"n":10.0}}', '{"n":10}'),
    ("jcs-num-neg-zero", "jcs/num-neg-zero", '{"value":{"n":-0.0}}', '{"n":0}'),
    ("jcs-num-1e16", "jcs/num-1e16-decimal", '{"value":{"n":1e16}}', '{"n":10000000000000000}'),
    ("jcs-num-1e21", "jcs/num-1e21-exponent", '{"value":{"n":1e21}}', '{"n":1e+21}'),
    ("jcs-num-1e-5", "jcs/num-1e-5-decimal", '{"value":{"n":1e-5}}', '{"n":0.00001}'),
    ("jcs-num-1e-6", "jcs/num-1e-6-decimal", '{"value":{"n":1e-6}}', '{"n":0.000001}'),
    ("jcs-num-1e-7", "jcs/num-1e-7-exponent", '{"value":{"n":1e-7}}', '{"n":1e-7}'),
    ("jcs-num-over-safe-int-raw", "jcs/num-over-safe-int-raw", '{"value":{"n":9007199254740993}}', '{"n":9007199254740992}'),
]
for fname, name, raw, expected in _num_cases:
    exp_bytes = expected.encode()
    write(f"{fname}.json", {
        "name": name, "command": "jcs", "input_raw": raw,
        "anchor": {"canonical_hex": exp_bytes.hex(), "byte_len": len(exp_bytes)},
    })

# non-finite input: 1e400 is valid JSON number syntax, so Go's json.Unmarshal
# copies it unparsed into json.RawMessage (no float conversion, go/vitni.go:28);
# rejection happens one layer down, at jcs.Transform, when it float-converts and
# finds +Inf. The bare NaN literal IS invalid JSON syntax, so that one errors at
# json.Unmarshal itself, before ever reaching jcs.Transform.
# JSON.parse turns 1e400 into Infinity (must be guarded) and rejects NaN.
# Both implementations MUST answer invalid_input.
write("neg-jcs-nonfinite-1e400.json", {
    "name": "jcs/nonfinite-1e400", "command": "jcs",
    "input_raw": '{"value":{"n":1e400}}', "anchor": {"error": "invalid_input"}})
write("neg-jcs-nan-literal.json", {
    "name": "jcs/nan-literal", "command": "jcs",
    "input_raw": '{"value":{"n":NaN}}', "anchor": {"error": "invalid_input"}})

# --- non-BMP key sort (#55): RFC 8785 §3.2.3 sorts by UTF-16 CODE UNITS.
# "😀" = surrogate pair D83D DE00; "�" = FFFD. D83D < FFFD, so 😀 sorts FIRST.
# A code-POINT sort (Python sorted()) puts � first — the anchor catches it.
# Canonical string is hand-built; jcs() (Python sort_keys) would be a WRONG oracle here.
_nonbmp_canonical = '{"\U0001F600":1,"�":2}'.encode()
write("jcs-nonbmp-key-sort.json", {
    "name": "jcs/nonbmp-key-sort-utf16", "command": "jcs",
    "input": {"value": {"\U0001F600": 1, "�": 2}},
    "anchor": {"canonical_hex": _nonbmp_canonical.hex(), "byte_len": len(_nonbmp_canonical)},
})

# --- CLI dispatch codes (#55): pin the previously off-vector paths.
# Go answers unsupported_command / invalid_input today; TS is aligned in the same change.
write("neg-cli-unsupported-command.json", {
    "name": "cli/unsupported-command", "command": "not-a-command",
    "input": {}, "anchor": {"error": "unsupported_command"}})
write("neg-cli-unparseable-stdin.json", {
    "name": "cli/unparseable-stdin", "command": "jcs",
    "input_raw": ")(", "anchor": {"error": "invalid_input"}})

# --- SSE non-finite bypass (#58): sse-jsonrpc carries JSON inside raw_b64, so the
# stdin-level non-finite guard never sees it. The inner result's 1e400 must be
# rejected at the decode-then-hash layer by both implementations (Go: jcs.Transform;
# TS: guard in the sse-jsonrpc path), never silently serialized as the bytes "null".
_raw_nonfinite = b'data: {"jsonrpc":"2.0","id":1,"result":{"n":1e400}}\n\n'
write("neg-sse-nonfinite-result.json", {
    "name": "sse/jsonrpc-nonfinite-result", "command": "sse-outputs-hash",
    "input": {"mode": "sse-jsonrpc", "raw_b64": base64.b64encode(_raw_nonfinite).decode()},
    "anchor": {"error": "invalid_input"}})

# --- SSE non-finite bypass (#58), NaN-message probe: `NaN` is not valid JSON, so a
# strict parser (Go's json.Unmarshal, TS's JSON.parse) fails to parse the message and
# CONTRACT §5 skip applies -> committed bytes are empty (empirically confirmed identical
# on both reference implementations). Anchored directly to the skip outcome rather than
# through sse_parse()'s jsonrpc branch: Python's json.loads accepts NaN by default
# (parse_constant), so running it through that oracle would wrongly include the message.
# This vector pins the skip outcome against a future Python impl making that same mistake.
_raw_nan_message = b'data: {"jsonrpc":"2.0","id":1,"result":NaN}\n\n'
_dec_nan_message = b""
write("sse-jsonrpc-nan-message.json", {
    "name": "sse/jsonrpc-nan-message", "command": "sse-outputs-hash",
    "input": {"mode": "sse-jsonrpc", "raw_b64": base64.b64encode(_raw_nan_message).decode()},
    "anchor": {"decoded_hex": _dec_nan_message.hex(), "outputs_hash": hashstr(_dec_nan_message)}})

# --- lone-surrogate escapes at the JCS-canonicalizing commands (#69 follow-up).
# input_raw keeps the backslash escapes intact through the harness. A surrogate
# escape is well-formed only as a HIGH (D800-DBFF) immediately followed by a LOW
# (DC00-DFFF) escape; anything else cannot be UTF-8 and MUST be invalid_input in
# every implementation. Hex digits are case-insensitive, so both cases are pinned.
_lone_cases = [
    ("neg-jcs-lone-high-upper", "jcs/lone-high-surrogate-uppercase", r'{"value":"\uD800"}'),
    ("neg-jcs-lone-low-upper", "jcs/lone-low-surrogate-uppercase", r'{"value":"\uDC00"}'),
    ("neg-jcs-high-then-char", "jcs/high-surrogate-then-char", r'{"value":"\uD800A"}'),
    ("neg-jcs-high-then-bmp-escape", "jcs/high-surrogate-then-bmp-escape", r'{"value":"\uD800\u0041"}'),
    ("neg-jcs-high-then-high-upper", "jcs/high-then-high-surrogate-uppercase", r'{"value":"\uD800\uD800"}'),
    ("neg-jcs-high-then-high-lower", "jcs/high-then-high-surrogate-lowercase", r'{"value":"\ud800\ud800"}'),
]
for fname, name, raw in _lone_cases:
    write(f"{fname}.json", {"name": name, "command": "jcs", "input_raw": raw,
                            "anchor": {"error": "invalid_input"}})

# a well-formed pair escape is accepted and canonicalizes to the raw character
_pair = '"\U0001F600"'.encode()
write("jcs-surrogate-pair-escape-upper.json", {
    "name": "jcs/surrogate-pair-escape-uppercase", "command": "jcs",
    "input_raw": r'{"value":"\uD83D\uDE00"}',
    "anchor": {"canonical_hex": _pair.hex(), "byte_len": len(_pair)}})

# surrogate escapes hide inside raw_b64 the same way 1e400 does, so the inner
# result must get the same strict-text rule as the stdin-level jcs commands.
_raw_lone = b'data: {"jsonrpc":"2.0","id":1,"result":"\\uD800\\uD800"}\n\n'
write("neg-sse-lone-surrogate-result.json", {
    "name": "sse/jsonrpc-lone-surrogate-result", "command": "sse-outputs-hash",
    "input": {"mode": "sse-jsonrpc", "raw_b64": base64.b64encode(_raw_lone).decode()},
    "anchor": {"error": "invalid_input"}})

# --- empty stdin (R0.10): a present-but-empty input_raw_b64 is EMPTY stdin, not
# "absent" (the Go CLI test used to treat an empty input_raw as absent and run
# the vector with whatever input it had). Both impls answer invalid_input. ---
write("neg-stdin-empty.json", {
    "name": "stdin/empty", "command": "jcs",
    "input_raw_b64": "", "anchor": {"error": "invalid_input"}})

# =====================================================================
# Stdin strictness (R0.8, R0.9, D5, D6, D8, D9). One stdin gate per impl serves
# every command, before dispatch: strict UTF-8, no BOM, no lone-surrogate
# escape, exactly one JSON value, an object, depth <= 128, no non-finite number
# anywhere in the text; duplicate keys rejected over the WHOLE text for jcs,
# receipt-id and cost-canon only. Violations are {"error":"invalid_input"}.
#
# `input_raw` carries the escape TEXT (six ASCII characters for a lone
# surrogate); `input_raw_b64` carries bytes a JSON string cannot (invalid UTF-8,
# BOM, NUL). Raw stdin is built from byte strings so nothing is re-encoded.
# =====================================================================
_INVALID = {"error": "invalid_input"}
_LONE_HI = "\\ud800"   # backslash-u-d800 as TEXT, not a surrogate character
_LONE_LO = "\\udc00"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _neg(fname: str, name: str, command: str, anchor=_INVALID, *, text=None, raw=None):
    """One stdin vector: `text` becomes input_raw, `raw` (bytes) becomes input_raw_b64."""
    assert (text is None) != (raw is None)
    vec = {"name": name, "command": command}
    if text is not None:
        vec["input_raw"] = text
    else:
        vec["input_raw_b64"] = _b64(raw)
    vec["anchor"] = anchor
    write(f"{fname}.json", vec)


def _receipt_text(**override) -> str:
    """The base receipt as JSON text with `override` members replaced by a marker."""
    return json.dumps({"receipt": dict(receipt, **{k: "PLACEHOLDER" for k in override})})


# lone surrogate escape (N1): TS keeps the lone surrogate and re-serializes it
# as an escape, Go turns it into U+FFFD; neither may answer.
_neg("neg-jcs-lone-surrogate-value", "stdin/jcs-lone-surrogate-value", "jcs",
     text='{"value":{"a":"' + _LONE_HI + '"}}')
_neg("neg-jcs-lone-surrogate-key", "stdin/jcs-lone-surrogate-key", "jcs",
     text='{"value":{"' + _LONE_HI + '":"x"}}')
# A lone LOW surrogate inside the envelope. Spec S0.61 sends the bare string
# "\udc00", which is invalid_input for being a non-object too; wrapping it in
# {"value": ...} makes the surrogate the only defect.
_neg("neg-jcs-lone-low-surrogate", "stdin/jcs-lone-low-surrogate", "jcs",
     text='{"value":"' + _LONE_LO + '"}')
_neg("neg-receipt-id-lone-surrogate", "stdin/receipt-id-lone-surrogate", "receipt-id",
     text=_receipt_text(method=0).replace("PLACEHOLDER", _LONE_HI))
_neg("neg-cost-canon-lone-surrogate", "stdin/cost-canon-lone-surrogate", "cost-canon",
     text='{"cost":{"tokens":"1","usd_micros":"0","wall_ms":"0","rail_ref":"' + _LONE_HI + '"}}')
# a member the command never reads is still parsed under the same policy
_neg("neg-digest-lone-surrogate-extra-member", "stdin/digest-lone-surrogate-extra-member", "digest",
     text='{"bytes_b64":"","x":"' + _LONE_HI + '"}')

# invalid UTF-8 (N2): Go echoes the raw byte, TS echoes U+FFFD.
_neg("neg-jcs-invalid-utf8", "stdin/jcs-invalid-utf8", "jcs",
     raw=b'{"value":{"a":"\xff"}}')
_neg("neg-receipt-id-invalid-utf8", "stdin/receipt-id-invalid-utf8", "receipt-id",
     raw=_receipt_text(method=0).encode().replace(b"PLACEHOLDER", b"\xff"))
_neg("neg-cost-canon-invalid-utf8", "stdin/cost-canon-invalid-utf8", "cost-canon",
     raw=b'{"cost":{"tokens":"1","usd_micros":"0","wall_ms":"0","rail_ref":"\xff"}}')

# BOM: both reject today (guards); the same rule must hold at the verify edge.
_neg("neg-jcs-bom", "stdin/jcs-bom", "jcs", raw=b'\xef\xbb\xbf{"value":1}')
_VERIFY_STUB = '{"signed_receipt":"a.b.c","keys":{},"policy":null'
_neg("neg-verify-stdin-bom", "stdin/verify-bom", "verify",
     raw=b'\xef\xbb\xbf' + (_VERIFY_STUB + '}').encode())
_neg("neg-verify-chain-stdin-bom", "stdin/verify-chain-bom", "verify-chain",
     raw=b'\xef\xbb\xbf{"receipts":[],"keys":{},"policy":null}')

# the envelope of verify is stdin text, not the signed envelope: a problem in it
# is a command error, never a {valid:false} verdict (R0.11)
_neg("neg-verify-stdin-lone-surrogate", "stdin/verify-lone-surrogate", "verify",
     text=_VERIFY_STUB + ',"x":"' + _LONE_HI + '"}')
_neg("neg-verify-nonfinite-extra-member", "stdin/verify-nonfinite-extra-member", "verify",
     text=_VERIFY_STUB + ',"x":1e400}')
_neg("neg-digest-nonfinite-extra-member", "stdin/digest-nonfinite-extra-member", "digest",
     text='{"bytes_b64":"","x":1e400}')

# one JSON value that is an object, and nothing after it
for _cmd in ("jcs", "hashstring", "digest", "verify", "verify-chain", "receipt-id", "cost-canon"):
    _neg(f"neg-stdin-array-{_cmd}", f"stdin/array-{_cmd}", _cmd, text="[]")
_neg("neg-stdin-trailing-garbage", "stdin/trailing-garbage", "digest",
     text='{"bytes_b64":""} x')
_neg("neg-stdin-nul-suffix", "stdin/nul-suffix", "digest", raw=b'{"bytes_b64":""}\x00')

# D5: a duplicate key in the ENVELOPE (not only inside the value) is rejected for
# the three canonicalizing commands; every other command keeps last-wins.
_neg("neg-jcs-dup-value-member", "stdin/jcs-dup-envelope-member", "jcs",
     text='{"value":1,"value":2}')
_neg("neg-receipt-id-dup-envelope", "stdin/receipt-id-dup-envelope", "receipt-id",
     text='{"receipt":{"v":"vitni/0.2"},"receipt":{"v":"x"}}')
_neg("neg-cost-canon-dup-envelope", "stdin/cost-canon-dup-envelope", "cost-canon",
     text='{"cost":{"tokens":"1","usd_micros":"0","wall_ms":"0","rail_ref":null},'
          '"cost":{"tokens":"2","usd_micros":"0","wall_ms":"0","rail_ref":null}}')
write("digest-dup-envelope-last-wins.json", {
    "name": "stdin/digest-dup-envelope-last-wins", "command": "digest",
    "input_raw": '{"bytes_b64":"","bytes_b64":"' + base64.b64encode(b"hello").decode() + '"}',
    "anchor": {"hashstr": hashstr(b"hello")}})

# D8: the command resolves before stdin is parsed
_neg("neg-cli-unsupported-command-bad-stdin", "cli/unsupported-command-bad-stdin",
     "not-a-command", {"error": "unsupported_command"}, text=")(")

# D9: nesting depth. The top-level object is depth 1; `value` adds the rest.
# 128 is accepted (guard), 129 is invalid_input. Neither host parser limit is
# relied on (Go 10000, V8 stack overflow).
_d128 = "[" * 127 + "]" * 127
_neg("neg-jcs-depth-129", "stdin/jcs-depth-129", "jcs",
     text='{"value":' + "[" * 128 + "]" * 128 + "}")
write("jcs-depth-128.json", {
    "name": "stdin/jcs-depth-128", "command": "jcs",
    "input_raw": '{"value":' + _d128 + "}",
    "anchor": {"canonical_hex": _d128.encode().hex(), "byte_len": len(_d128)}})

# =====================================================================
# Exact member names and required members (D4, D7, N3, Q8; sweep 0b.16).
# Member names are exact and case-sensitive: a name that differs only in case
# is an UNKNOWN member (ignored), never a match (Go's encoding/json matches
# case-insensitively). A required member that is absent or null, or has the
# wrong JSON type, is invalid_input. Absent-but-optional members keep their
# existing outcome (sign kid / private_key_b64, verify signed_receipt).
#
# Per-command input table (PR body of 0b):
#   jcs                value:any(required, null allowed)
#   hashstring         algo:string(required, == "sha2-256")  digest_hex:string(required)
#   digest             bytes_b64:string(required)
#   receipt-id         receipt:object(required)
#   sse-outputs-hash   raw_b64:string(required)  mode:string(required, sse | sse-jsonrpc)
#   cost-canon         cost:object(required)
#   verify             signed_receipt:string|null  keys:object|null  policy:object|null
#   verify-chain       receipts:array<string>|null  keys:object|null  policy:object|null
#   a2a-artifact-hash  artifact:object(required)  artifact.parts:array<object>(required)
#                      part.kind:string|null  part.file:object|null
#   sign               receipt:object(required)  kid:string|null  private_key_b64:string|null
#   keygen             seed_b64: any, judged by the command (non-string is invalid_seed)
# =====================================================================
_SHA_HELLO = hashlib.sha256(b"hello").hexdigest()
_MCP_TEXT = json.dumps(receipt)

# D4: names that differ only in case
_neg("neg-jcs-member-case-value", "member/jcs-case-value", "jcs", text='{"VALUE":{"a":1}}')
_neg("neg-digest-member-case-bytes-b64", "member/digest-case-bytes-b64", "digest",
     text='{"BYTES_B64":"aGVsbG8="}')
_neg("neg-hashstring-member-case-algo", "member/hashstring-case-algo", "hashstring",
     text='{"ALGO":"sha2-256","digest_hex":"' + _SHA_HELLO + '"}')
_neg("neg-receipt-id-member-case-receipt", "member/receipt-id-case-receipt", "receipt-id",
     text='{"Receipt":' + _MCP_TEXT + '}')
_neg("neg-cost-canon-member-case-cost", "member/cost-canon-case-cost", "cost-canon",
     text='{"COST":{"tokens":"1","usd_micros":"0","wall_ms":"0","rail_ref":null}}')
_neg("neg-sse-member-case-mode", "member/sse-case-mode", "sse-outputs-hash",
     text='{"MODE":"sse","raw_b64":""}')
_neg("neg-a2a-member-case-artifact", "member/a2a-case-artifact", "a2a-artifact-hash",
     text='{"ARTIFACT":{"parts":[]}}')
_neg("neg-a2a-member-case-parts", "member/a2a-case-parts", "a2a-artifact-hash",
     text='{"artifact":{"PARTS":[]}}')
_neg("neg-a2a-member-case-kind", "member/a2a-case-kind", "a2a-artifact-hash",
     text='{"artifact":{"parts":[{"KIND":"text","text":"x"}]}}', anchor={"error": "unsupported_part"})
_neg("neg-sign-member-case-receipt", "member/sign-case-receipt", "sign",
     text='{"Receipt":' + _MCP_TEXT + ',"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}')
write("verify-chain-member-case-receipts.json", {
    "name": "member/verify-chain-case-receipts", "command": "verify-chain",
    "input_raw": '{"Receipts":["a.b.c"],"keys":{},"policy":null}',
    "anchor": {"valid": False, "reason": "empty_chain", "chain_len": 0}})

# D7: absent required members (Q8: jcs {} is invalid_input, not a printed null)
_neg("neg-jcs-value-missing", "member/jcs-value-missing", "jcs", text="{}")
_neg("neg-digest-missing-bytes", "member/digest-missing-bytes", "digest", text="{}")
_neg("neg-receipt-id-missing-receipt", "member/receipt-id-missing-receipt", "receipt-id", text="{}")
_neg("neg-cost-canon-missing-cost", "member/cost-canon-missing-cost", "cost-canon", text="{}")
_neg("neg-hashstring-missing-digest-hex", "member/hashstring-missing-digest-hex", "hashstring",
     text='{"algo":"sha2-256"}')
_neg("neg-sse-missing-raw-b64", "member/sse-missing-raw-b64", "sse-outputs-hash",
     text='{"mode":"sse"}')
_neg("neg-sse-missing-mode", "member/sse-missing-mode", "sse-outputs-hash", text='{"raw_b64":""}')
_neg("neg-a2a-missing-artifact", "member/a2a-missing-artifact", "a2a-artifact-hash", text="{}")
_neg("neg-a2a-missing-parts", "member/a2a-missing-parts", "a2a-artifact-hash",
     text='{"artifact":{}}')
_neg("neg-sign-missing-receipt", "member/sign-missing-receipt", "sign",
     text='{"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}')
# null is "absent" for a required member
_neg("neg-digest-bytes-null", "member/digest-bytes-null", "digest", text='{"bytes_b64":null}')
_neg("neg-hashstring-algo-null", "member/hashstring-algo-null", "hashstring",
     text='{"algo":null,"digest_hex":"' + _SHA_HELLO + '"}')
_neg("neg-hashstring-digest-hex-null", "member/hashstring-digest-hex-null", "hashstring",
     text='{"algo":"sha2-256","digest_hex":null}')
_neg("neg-receipt-id-receipt-null", "member/receipt-id-receipt-null", "receipt-id",
     text='{"receipt":null}')
_neg("neg-cost-canon-cost-null", "member/cost-canon-cost-null", "cost-canon", text='{"cost":null}')
_neg("neg-sse-raw-b64-null", "member/sse-raw-b64-null", "sse-outputs-hash",
     text='{"mode":"sse","raw_b64":null}')
_neg("neg-sse-mode-null", "member/sse-mode-null", "sse-outputs-hash",
     text='{"mode":null,"raw_b64":""}')
_neg("neg-a2a-artifact-null", "member/a2a-artifact-null", "a2a-artifact-hash",
     text='{"artifact":null}')
_neg("neg-a2a-parts-null", "member/a2a-parts-null", "a2a-artifact-hash",
     text='{"artifact":{"parts":null}}')
_neg("neg-sign-receipt-null", "member/sign-receipt-null", "sign",
     text='{"receipt":null,"kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}')
# a JSON null IS a value for jcs (canonical form "null"): guard against reading
# "null is absent" into the one member whose domain includes null
write("jcs-value-null.json", {
    "name": "member/jcs-value-null", "command": "jcs", "input_raw": '{"value":null}',
    "anchor": {"canonical_hex": b"null".hex(), "byte_len": 4}})
# optional members keep their existing outcome when absent or null
_neg("neg-sign-kid-null", "member/sign-kid-null", "sign",
     {"error": "kid_required"},
     text='{"receipt":' + _MCP_TEXT + ',"kid":null,"private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}')
_neg("neg-sign-private-key-missing", "member/sign-private-key-missing", "sign",
     {"error": "invalid_private_key"}, text='{"receipt":' + _MCP_TEXT + ',"kid":"ed-1"}')

# N3: hashstring algo, exactly "sha2-256"; the retired `unsupported_algo` code is gone
_neg("neg-hashstring-unsupported-algo", "member/hashstring-unsupported-algo", "hashstring",
     text='{"algo":"sha3","digest_hex":"' + _SHA_HELLO + '"}')
_neg("neg-hashstring-algo-missing", "member/hashstring-algo-missing", "hashstring",
     text='{"digest_hex":"' + _SHA_HELLO + '"}')
_neg("neg-hashstring-algo-number", "member/hashstring-algo-number", "hashstring",
     text='{"algo":1,"digest_hex":"' + _SHA_HELLO + '"}')
_neg("neg-sse-unsupported-mode", "member/sse-unsupported-mode", "sse-outputs-hash",
     text='{"mode":"xml","raw_b64":""}')

# wrong JSON types
_neg("neg-digest-bytes-number", "member/digest-bytes-number", "digest", text='{"bytes_b64":5}')
_neg("neg-hashstring-digest-hex-number", "member/hashstring-digest-hex-number", "hashstring",
     text='{"algo":"sha2-256","digest_hex":5}')
_neg("neg-receipt-id-receipt-number", "member/receipt-id-receipt-number", "receipt-id",
     text='{"receipt":5}')
_neg("neg-receipt-id-receipt-array", "member/receipt-id-receipt-array", "receipt-id",
     text='{"receipt":[]}')
_neg("neg-cost-canon-cost-array", "member/cost-canon-cost-array", "cost-canon", text='{"cost":[]}')
_neg("neg-cost-canon-cost-string", "member/cost-canon-cost-string", "cost-canon", text='{"cost":"x"}')
_neg("neg-sse-raw-b64-number", "member/sse-raw-b64-number", "sse-outputs-hash",
     text='{"mode":"sse","raw_b64":5}')
_neg("neg-sse-mode-number", "member/sse-mode-number", "sse-outputs-hash",
     text='{"mode":5,"raw_b64":""}')
_neg("neg-a2a-artifact-array", "member/a2a-artifact-array", "a2a-artifact-hash",
     text='{"artifact":[]}')
_neg("neg-a2a-parts-string", "member/a2a-parts-string", "a2a-artifact-hash",
     text='{"artifact":{"parts":"x"}}')
_neg("neg-a2a-part-number", "member/a2a-part-number", "a2a-artifact-hash",
     text='{"artifact":{"parts":[5]}}')
_neg("neg-a2a-kind-number", "member/a2a-kind-number", "a2a-artifact-hash",
     text='{"artifact":{"parts":[{"kind":5}]}}')
_neg("neg-a2a-file-string", "member/a2a-file-string", "a2a-artifact-hash",
     text='{"artifact":{"parts":[{"kind":"file","file":"x"}]}}')
_neg("neg-a2a-file-bytes-number", "member/a2a-file-bytes-number", "a2a-artifact-hash",
     text='{"artifact":{"parts":[{"kind":"file","file":{"bytes":5}}]}}')
_neg("neg-sign-receipt-string", "member/sign-receipt-string", "sign",
     text='{"receipt":"x","kid":"ed-1","private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}')
_neg("neg-sign-kid-number", "member/sign-kid-number", "sign",
     text='{"receipt":' + _MCP_TEXT + ',"kid":5,"private_key_b64":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}')
_neg("neg-sign-private-key-number", "member/sign-private-key-number", "sign",
     text='{"receipt":' + _MCP_TEXT + ',"kid":"ed-1","private_key_b64":5}')
_neg("neg-verify-chain-receipts-string", "member/verify-chain-receipts-string", "verify-chain",
     text='{"receipts":"x","keys":{},"policy":null}')
_neg("neg-verify-chain-receipt-number", "member/verify-chain-receipt-number", "verify-chain",
     text='{"receipts":[5],"keys":{},"policy":null}')
write("verify-chain-receipts-null.json", {
    "name": "member/verify-chain-receipts-null", "command": "verify-chain",
    "input_raw": '{"receipts":null,"keys":{},"policy":null}',
    "anchor": {"valid": False, "reason": "empty_chain", "chain_len": 0}})

# =====================================================================
# Embedded parse sites (R0.9). The sse-jsonrpc inner message is JSON text hidden
# inside raw_b64, so the stdin gate never sees it. It must go through the same
# strict text function: no lone-surrogate escape, no non-finite number anywhere in
# the message, depth <= 128; duplicate keys stay last-wins; text that is not JSON
# at all keeps being skipped (CONTRACT section 5). Violations: invalid_input.
# a2a parts are NOT an embedded site: they are members of the stdin object, so
# the stdin gate has already judged them (the a2a vectors below prove it).
# =====================================================================
def _sse_jsonrpc(fname, name, message: bytes, anchor):
    raw = b"data: " + message + b"\n\n"
    write(f"{fname}.json", {
        "name": name, "command": "sse-outputs-hash",
        "input": {"mode": "sse-jsonrpc", "raw_b64": base64.b64encode(raw).decode()},
        "anchor": anchor})


def _sse_committed(fname, name, message: bytes, committed: bytes):
    _sse_jsonrpc(fname, name, message,
                 {"decoded_hex": committed.hex(), "outputs_hash": hashstr(committed)})


_sse_jsonrpc("neg-sse-jsonrpc-inner-lone-surrogate", "sse/jsonrpc-inner-lone-surrogate",
             b'{"jsonrpc":"2.0","id":1,"result":"' + _LONE_HI.encode() + b'"}', _INVALID)
# the policy covers the whole message, not only the member the command reads
_sse_jsonrpc("neg-sse-jsonrpc-inner-lone-surrogate-ignored-member",
             "sse/jsonrpc-inner-lone-surrogate-ignored-member",
             b'{"jsonrpc":"2.0","id":"' + _LONE_HI.encode() + b'","result":1}', _INVALID)
_sse_jsonrpc("neg-sse-jsonrpc-inner-nonfinite-ignored-member",
             "sse/jsonrpc-inner-nonfinite-ignored-member",
             b'{"jsonrpc":"2.0","id":1e400,"result":1}', _INVALID)
# nesting depth is counted from the inner message itself (its own top level is depth 1)
_sse_jsonrpc("neg-sse-jsonrpc-inner-depth-129", "sse/jsonrpc-inner-depth-129",
             b'{"result":' + b"[" * 128 + b"]" * 128 + b"}", _INVALID)
# far beyond encoding/json's own depth cap (10000), which stops calling such text
# JSON at all: the limit is the protocol's, never the host parser's
_sse_jsonrpc("neg-sse-jsonrpc-inner-depth-20000", "sse/jsonrpc-inner-depth-20000",
             b'{"result":' + b"[" * 20000 + b"]" * 20000 + b"}", _INVALID)
_nest127 = b"[" * 127 + b"]" * 127
_sse_committed("sse-jsonrpc-inner-depth-128", "sse/jsonrpc-inner-depth-128",
               b'{"result":' + _nest127 + b"}", _nest127)
# duplicate keys inside the inner message are last-wins (not rejected)
_sse_committed("sse-jsonrpc-inner-dup-last-wins", "sse/jsonrpc-inner-dup-last-wins",
               b'{"result":1,"result":2}', b"2")
# mode sse never parses the data as JSON: an escape that would be a lone
# surrogate is just text
_lone_text = b'{"result":"' + _LONE_HI.encode() + b'"}'
write("sse-plain-lone-surrogate-escape-is-text.json", {
    "name": "sse/plain-lone-surrogate-escape-is-text", "command": "sse-outputs-hash",
    "input": {"mode": "sse", "raw_b64": base64.b64encode(b"data: " + _lone_text + b"\n\n").decode()},
    "anchor": {"decoded_hex": _lone_text.hex(), "outputs_hash": hashstr(_lone_text)}})

# a2a: the stdin gate already judges the parts
_neg("neg-a2a-part-lone-surrogate", "a2a/part-lone-surrogate", "a2a-artifact-hash",
     text='{"artifact":{"parts":[{"kind":"text","text":"' + _LONE_HI + '"}]}}')
_neg("neg-a2a-data-depth-129", "a2a/data-depth-129", "a2a-artifact-hash",
     text='{"artifact":{"parts":[{"kind":"data","data":' + "[" * 125 + "]" * 125 + "}]}}")
_a2a_nest = "[" * 124 + "]" * 124
_a2a_desc = jcs({"parts": [{"kind": "data", "data": json.loads(_a2a_nest)}]}).encode()
write("a2a-data-depth-128.json", {
    "name": "a2a/data-depth-128", "command": "a2a-artifact-hash",
    "input_raw": '{"artifact":{"parts":[{"kind":"data","data":' + _a2a_nest + "}]}}",
    "anchor": {"descriptor_hex": _a2a_desc.hex(), "outputs_hash": hashstr(_a2a_desc)}})


# =====================================================================
# Former hand-authored vectors (keygen, seed and std-base64 edge cases). They
# live here so that deleting conformance/vectors/*.json and rerunning the
# generators restores every file: no vector is owned by a person.
# =====================================================================
# RFC 8032 section 7.1 TEST 1: the Ed25519 secret key (seed) and the public key
# it derives. The anchor is a published constant, so _gen.py needs no crypto
# dependency and the anchor is independent of both implementations under test.
_RFC8032_T1_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_RFC8032_T1_PUB = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_T1_SEED_B64 = base64.b64encode(_RFC8032_T1_SEED).decode()
write("keygen-derive-valid.json", {
    "name": "keygen/derive-valid", "command": "keygen",
    "input": {"seed_b64": _T1_SEED_B64},
    "anchor": {"jwk": {"alg": "EdDSA", "crv": "Ed25519", "kty": "OKP", "status": "active",
                       "x": b64url_nopad(_RFC8032_T1_PUB)},
               "private_key_b64": _T1_SEED_B64}})

# 32 bytes 01..20 as std base64, and the malformed variants of it
_SEQ32 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
_SEQ32_NEWLINE = "AQIDBAUGBwgJCgsMDQ4P\nEBESExQVFhcYGRobHB0eHyA="
_SEQ32_EXCESS_PAD = _SEQ32 + "="
_SEQ32_TRAILING_BITS = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB="


def _keygen_seed(fname, name, seed, code="invalid_seed"):
    write(fname, {"name": name, "command": "keygen", "input": {"seed_b64": seed},
                  "anchor": {"error": code}})


_keygen_seed("keygen-seed-embedded-newline.json", "keygen/seed-embedded-newline", _SEQ32_NEWLINE)
_keygen_seed("keygen-seed-empty-string.json", "keygen/seed-empty-string", "")
_keygen_seed("keygen-seed-excess-padding.json", "keygen/seed-excess-padding", _SEQ32_EXCESS_PAD)
_keygen_seed("keygen-seed-malformed-b64.json", "keygen/seed-malformed-b64", "!!!not-base64!!!")
_keygen_seed("keygen-seed-non-string.json", "keygen/seed-non-string", 123)
_keygen_seed("keygen-seed-trailing-bits.json", "keygen/seed-nonzero-trailing-bits", _SEQ32_TRAILING_BITS)
_keygen_seed("keygen-seed-wrong-length.json", "keygen/seed-wrong-length", "AQIDBAUGBwgJCgsMDQ4PEA==")
write("keygen-unknown-key.json", {
    "name": "keygen/unknown-key", "command": "keygen",
    "input": {"seed_b64": _T1_SEED_B64, "kid": "x"}, "anchor": {"error": "invalid_input"}})

write("neg-a2a-embedded-newline-inline-b64.json", {
    "name": "a2a-artifact-hash/embedded-newline-inline-base64", "command": "a2a-artifact-hash",
    "input": {"artifact": {"parts": [{"kind": "file", "file": {"bytes": "aGVs\nbG8="}}]}},
    "anchor": {"error": "invalid_input"}})

for _f, _n, _b in (
        ("neg-digest-embedded-newline-b64.json", "digest/embedded-newline", "aGVs\nbG8="),
        ("neg-digest-excess-padding-b64.json", "digest/excess-padding", "aGVsbG8=="),
        ("neg-digest-trailing-bits-b64.json", "digest/nonzero-trailing-bits", "aGVsbG9")):
    write(_f, {"name": _n, "command": "digest", "input": {"bytes_b64": _b},
               "anchor": {"error": "invalid_input"}})

_SIGN_RECEIPT = {
    "v": "vitni/0.2", "binding": "mcp", "action_ref": None, "performer_id": "srv-ed",
    "requester_id": None, "method": "mcp:echo",
    "inputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
    "outputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
    "cost": {"tokens": "10", "usd_micros": "0", "wall_ms": "3", "rail_ref": None},
    "status": "OK", "reason": None, "parent_receipt_hash": None,
    "log_policy": "best_effort", "ts": "2026-05-28T00:00:00Z",
    "nonce": "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ"}
for _f, _n, _s in (
        ("neg-sign-seed-embedded-newline.json", "sign/seed-embedded-newline", _SEQ32_NEWLINE),
        ("neg-sign-seed-excess-padding.json", "sign/seed-excess-padding", _SEQ32_EXCESS_PAD),
        ("neg-sign-seed-trailing-bits.json", "sign/seed-nonzero-trailing-bits", _SEQ32_TRAILING_BITS)):
    write(_f, {"name": _n, "command": "sign",
               "input": {"receipt": _SIGN_RECEIPT, "kid": "ed-1", "private_key_b64": _s},
               "anchor": {"error": "invalid_private_key"}})
