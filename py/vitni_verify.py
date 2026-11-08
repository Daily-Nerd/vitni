"""vitni verify-only reference verifier (Python, standard library only).

Contract
--------
Run as `python -I py/vitni_verify.py <command>`. It reads the command's input
object from stdin (bytes) and writes exactly one line to stdout: JCS-canonical
JSON followed by LF, exit code 0 on every handled path. Nothing else goes to
stdout. A command the CLI does not know is {"error":"unsupported_command"}, no
command at all is {"error":"missing_command"}.

Declared commands: verify, jcs, digest, hashstring, receipt-id and profiles.
The commands a2a-artifact-hash, cost-canon, keygen, sign, sse-outputs-hash and
verify-chain exist in the protocol but not here: they answer
{"error":"unsupported_profile","profile":"cmd:<command>"} without reading stdin.

ES256 signatures are raw R||S, exactly 64 bytes. There is no DER path.

Importable API: verify(signed_receipt, keys=None, policy=None) returns the same
dict the CLI prints, never raises for any input.

Mapping for a caller that vendors this file: {"valid":true} is verified,
{"valid":false} is failed, any {"error":...} is unable (no judgement made).

Pin
---
Callers pin the sha256 of this file (shasum -a 256 py/vitni_verify.py), so
editing this file changes its pinned sha256 and is a release decision, not a
cleanup. The file carries no version stamp and no date for that reason, and no
formatter may rewrite it.
"""

import base64
import hashlib
import json
import math
import re
import sys

# --------------------------------------------------------------------------
# Errors. Control flow only: none of these ever escapes the module.
# --------------------------------------------------------------------------


class _Reject(Exception):
    """An input was refused by a strict decoder. The call site picks the code."""


class _NotCanonical(_Reject):
    """A value has no canonical (JCS) serialization, e.g. a non-finite number."""


# --------------------------------------------------------------------------
# Byte decoders: exactly one per input format. Each rejects what the stdlib
# default would accept; each is the only place its stdlib module is used.
# --------------------------------------------------------------------------

_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_B64STD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")


def utf8_decode_strict(data):
    """Strict UTF-8 text: no BOM, no overlong forms, no encoded surrogates."""
    if not isinstance(data, (bytes, bytearray)):
        raise _Reject("not bytes")
    if bytes(data[:3]) == b"\xef\xbb\xbf":
        raise _Reject("BOM")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise _Reject("invalid UTF-8") from None


def b64url_decode_strict(s):
    """Unpadded base64url, alphabet A-Za-z0-9-_ only, canonical trailing bits."""
    if not isinstance(s, str) or _B64URL.fullmatch(s) is None or len(s) % 4 == 1:
        raise _Reject("base64url")
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise _Reject("base64url") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=") != s.encode("ascii"):
        raise _Reject("base64url trailing bits")
    return raw


def b64std_decode_strict(s):
    """Standard base64, canonical padded or canonical unpadded, nothing else."""
    if not isinstance(s, str) or _B64STD.fullmatch(s) is None:
        raise _Reject("base64")
    body = s.rstrip("=")
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except ValueError:
        raise _Reject("base64") from None
    padded = base64.b64encode(raw)
    if s.encode("ascii") not in (padded, padded.rstrip(b"=")):
        raise _Reject("base64 not canonical")
    return raw


def hex_decode_strict(s):
    """Even-length hex of either case. bytes.fromhex would skip whitespace."""
    if not isinstance(s, str) or _HEX.fullmatch(s) is None:
        raise _Reject("hex")
    return bytes.fromhex(s)


def b64url_encode(raw):
    """Unpadded base64url text. Goes through utf8_decode_strict, the one decoder."""
    return utf8_decode_strict(base64.urlsafe_b64encode(raw).rstrip(b"="))


# --------------------------------------------------------------------------
# Strict JSON text. parse_json is the only json.loads call in this file.
# --------------------------------------------------------------------------

MAX_DEPTH = 128  # nesting limit of the protocol, never the host parser's


class _NonFinite:
    """Stands in for a number that overflowed to infinity, under nonfinite="defer"."""

    __slots__ = ()

    def __repr__(self):
        return "<non-finite>"


_NONFINITE = _NonFinite()

_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]', re.DOTALL)
_SURROGATE = re.compile("[\\ud800-\\udfff]")


def _within_depth(text):
    """One raw scan with string state: the top-level value is depth 1."""
    depth = 0
    for m in _TOKEN.finditer(text):
        c = m.group()
        if c == "[" or c == "{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif c == "]" or c == "}":
            depth -= 1
    return True


def _has_lone_surrogate(root):
    """Paired escapes were already combined by json, so any surrogate left is lone."""
    stack = [root]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if _SURROGATE.search(v):
                return True
        elif isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                if _SURROGATE.search(k):
                    return True
                stack.append(x)
    return False


def _no_constant(name):
    raise _Reject("constant " + name)


def parse_json(data, *, dup, nonfinite):
    """Strict JSON text -> value, with the site's policy stated by the caller.

    dup: "reject" (any duplicate key, at any depth) or "last".
    nonfinite: "reject" (a number that overflows to infinity) or "defer" (it
    becomes the _NONFINITE sentinel, which jcs refuses). Numbers are always
    doubles, parsed by float(str): int() on text has a digit limit that exists
    on 3.11+ and not on 3.10.
    """
    if dup not in ("reject", "last") or nonfinite not in ("reject", "defer"):
        raise ValueError("unknown parse policy")
    text = utf8_decode_strict(data)
    if not _within_depth(text):
        raise _Reject("too deep")

    def num(s):
        v = float(s)
        if math.isinf(v):
            if nonfinite == "reject":
                raise _Reject("non-finite number")
            return _NONFINITE
        return v

    def pairs(items):
        d = {}
        for k, v in items:
            if dup == "reject" and k in d:
                raise _Reject("duplicate key")
            d[k] = v
        return d

    try:
        value = json.loads(text, parse_constant=_no_constant, parse_float=num, parse_int=num, object_pairs_hook=pairs)
    except (json.JSONDecodeError, RecursionError):
        raise _Reject("json") from None
    if _has_lone_surrogate(value):
        raise _Reject("lone surrogate")
    return value


# --------------------------------------------------------------------------
# JCS (RFC 8785). Written out by hand: no json.dumps, so no hidden defaults.
# --------------------------------------------------------------------------

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_NEEDS_ESCAPE = re.compile('["\\\\\\x00-\\x1f]')


def _escape(m):
    c = m.group()
    return _ESCAPES.get(c) or "\\u%04x" % ord(c)


def _es_number(f):
    """ECMAScript Number::toString of a finite double, from the shortest
    round-trip digits that repr() already produces."""
    if f == 0.0:
        return "0"
    sign = "-" if f < 0 else ""
    mantissa, _, exp = repr(abs(f)).partition("e")
    whole, _, frac = mantissa.partition(".")
    digits = whole + frac
    n = len(whole) + (int(exp) if exp else 0)  # value = 0.<digits> x 10^n
    stripped = digits.lstrip("0")
    n -= len(digits) - len(stripped)
    d = stripped.rstrip("0")
    k = len(d)
    if k <= n <= 21:
        body = d + "0" * (n - k)
    elif 0 < n <= 21:
        body = d[:n] + "." + d[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + d
    else:
        e = n - 1
        body = d[0] + ("." + d[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + body


def _jcs_text(v):
    if v is None:
        return "null"
    if v is True:  # bool is an int subclass: test it before the numbers
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return '"' + _NEEDS_ESCAPE.sub(_escape, v) + '"'
    if isinstance(v, (int, float)):
        try:
            f = float(v)
        except OverflowError:
            raise _NotCanonical("number overflows a double") from None
        if not math.isfinite(f):
            raise _NotCanonical("non-finite number")
        return _es_number(f)
    if isinstance(v, list):
        return "[" + ",".join(_jcs_text(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=_utf16_key)
        return "{" + ",".join(_jcs_text(k) + ":" + _jcs_text(v[k]) for k in keys) + "}"
    raise _NotCanonical("not a JSON value")  # includes the _NONFINITE sentinel


def _utf16_key(k):
    try:
        return k.encode("utf-16-be")
    except UnicodeEncodeError:
        raise _NotCanonical("lone surrogate in key") from None


def jcs(value):
    """The RFC 8785 canonical bytes of a parsed JSON value."""
    try:
        return _jcs_text(value).encode("utf-8")
    except UnicodeEncodeError:
        raise _NotCanonical("lone surrogate") from None


# --------------------------------------------------------------------------
# Hashes and ids. Each command handler takes the already-parsed, already
# shape-checked stdin object and returns the result dict; a bad value inside a
# member raises _Reject (the CLI answers invalid_input).
# --------------------------------------------------------------------------


def hashstring(digest):
    """Pinned hash-string: 'u' + base64url(multihash code 0x12, length 0x20, digest)."""
    return "u" + b64url_encode(b"\x12\x20" + digest)


def _cmd_hashstring(inp):
    if inp["algo"] != "sha2-256":
        raise _Reject("algo")
    return {"hashstr": hashstring(hex_decode_strict(inp["digest_hex"]))}


def _cmd_digest(inp):
    return {"hashstr": hashstring(hashlib.sha256(b64std_decode_strict(inp["bytes_b64"])).digest())}


def _cmd_receipt_id(inp):
    receipt = inp["receipt"]
    if "receipt_id" in receipt:
        return {"error": "receipt_id_must_be_absent"}
    canonical = jcs(receipt)
    return {"canonical_hex": canonical.hex(), "receipt_id": hashstring(hashlib.sha256(canonical).digest())}


def _cmd_jcs(inp):
    canonical = jcs(inp["value"])
    return {"byte_len": len(canonical), "canonical_hex": canonical.hex()}


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032 arithmetic, verification as Go and OpenSSL decide it).
# Cofactorless: accept iff encode([S]B - [k]A) == R_enc. R is never decoded, so
# a non-canonical R fails. A is decoded with y reduced mod p and x = 0 with the
# sign bit set accepted. k hashes the ORIGINAL 32 public-key bytes, never a
# re-encoding. No small-order, identity-key or torsion rejection.
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_recover_x(y, sign):
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None  # not a square: no such point
    if x & 1 != sign:
        x = (_P - x) % _P  # x = 0 with sign 1 stays 0, accepted
    return x


def _ed_add(p, q):
    """Complete unified addition on extended coordinates (X, Y, Z, T)."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = p[3] * 2 * _D * q[3] % _P
    d = p[2] * 2 * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s, p):
    r = (0, 1, 1, 0)
    for i in range(s.bit_length() - 1, -1, -1):
        r = _ed_add(r, r)
        if (s >> i) & 1:
            r = _ed_add(r, p)
    return r


def _ed_encode(p):
    zinv = pow(p[2], -1, _P)
    x, y = p[0] * zinv % _P, p[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_ED_BY = 4 * pow(5, -1, _P) % _P
_ED_BX = _ed_recover_x(_ED_BY, 0)
_ED_B = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _P)


def _ed25519_verify(pub, sig, msg):
    if len(pub) != 32 or len(sig) != 64:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    y = (int.from_bytes(pub, "little") & (2 ** 255 - 1)) % _P
    x = _ed_recover_x(y, pub[31] >> 7)
    if x is None:
        return False
    neg_a = ((-x) % _P, y, 1, (-x * y) % _P)
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    return _ed_encode(_ed_add(_ed_mul(s, _ED_B), _ed_mul(k, neg_a))) == sig[:32]


# --------------------------------------------------------------------------
# P-256 ECDSA (ES256). Jacobian coordinates, a = -3, infinity is Z == 0. Every
# edge case (equal points, opposite points, infinity operands) goes through one
# complete _jadd; there is no Shamir trick to special-case. Signatures are the
# raw 64-byte R||S of JWS and nothing else.
# --------------------------------------------------------------------------

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
_JINF = (1, 1, 0)


def _jdouble(pt):
    x, y, z = pt
    if z == 0 or y == 0:
        return _JINF
    p = _P256_P
    delta, gamma = z * z % p, y * y % p
    beta = x * gamma % p
    alpha = 3 * (x - delta) * (x + delta) % p
    x3 = (alpha * alpha - 8 * beta) % p
    z3 = ((y + z) ** 2 - gamma - delta) % p
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p
    return (x3, y3, z3)


def _jadd(a, b):
    if a[2] == 0:
        return b
    if b[2] == 0:
        return a
    p = _P256_P
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1z1, z2z2 = z1 * z1 % p, z2 * z2 % p
    u1, u2 = x1 * z2z2 % p, x2 * z1z1 % p
    s1, s2 = y1 * z2 * z2z2 % p, y2 * z1 * z1z1 % p
    if u1 == u2:
        return _jdouble(a) if s1 == s2 else _JINF
    h = (u2 - u1) % p
    i = (2 * h) ** 2 % p
    j = h * i % p
    r = 2 * (s2 - s1) % p
    v = u1 * i % p
    x3 = (r * r - j - 2 * v) % p
    y3 = (r * (v - x3) - 2 * s1 * j) % p
    z3 = (((z1 + z2) ** 2 - z1z1 - z2z2) * h) % p
    return (x3, y3, z3)


def _jmul(k, pt):
    r = _JINF
    for i in range(k.bit_length() - 1, -1, -1):
        r = _jdouble(r)
        if (k >> i) & 1:
            r = _jadd(r, pt)
    return r


def _p256_mul_add(u1, u2, q):
    """Affine u1*G + u2*Q as two multiplications and one complete add, or None
    for the point at infinity."""
    gx, gy = _P256_G
    x, y, z = _jadd(_jmul(u1, (gx, gy, 1)), _jmul(u2, (q[0], q[1], 1)))
    if z == 0:
        return None
    zi = pow(z, -1, _P256_P)
    return (x * zi * zi % _P256_P, y * zi * zi * zi % _P256_P)


def _p256_digest_int(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % _P256_N


def _p256_verify(x, y, sig, msg):
    if len(sig) != 64 or len(x) != 32 or len(y) != 32:
        return False
    p, n = _P256_P, _P256_N
    qx, qy = int.from_bytes(x, "big"), int.from_bytes(y, "big")
    if qx >= p or qy >= p or (qy * qy - qx ** 3 + 3 * qx - _P256_B) % p:
        return False  # coordinate out of range, or not on the curve ((0, 0) included)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False  # high S is fine: no low-S rule
    w = pow(s, -1, n)
    point = _p256_mul_add(_p256_digest_int(msg) * w % n, r * w % n, (qx, qy))
    return point is not None and point[0] % n == r


# --------------------------------------------------------------------------
# The algorithm table: the single owner of alg -> (kty, crv, key coordinates,
# verify function). Key-type binding, key decoding and the declared alg atoms
# all derive from it.
# --------------------------------------------------------------------------

ALGS = {
    "EdDSA": ("OKP", "Ed25519", ("x",), _ed25519_verify),
    "ES256": ("EC", "P-256", ("x", "y"), _p256_verify),
}


# --------------------------------------------------------------------------
# verify: CONTRACT steps 1 to 8, the first failing step wins.
# --------------------------------------------------------------------------

_FORBIDDEN_HEADER = ("jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256")
_ENTRY_MEMBERS = ("kty", "crv", "x", "y", "alg", "status")
_POLICY_MEMBERS = ("expected_binding", "expected_method")


def _typed(obj, members):
    """obj is a dict whose named members are each a string, None or absent."""
    return isinstance(obj, dict) and all(obj.get(m) is None or isinstance(obj[m], str) for m in members)


def _verify_shape(signed_receipt, keys, policy):
    """The whole keys tree and the policy are typed, not only the entry a receipt
    resolves to. A wrong type is a command error, never a verdict."""
    if signed_receipt is not None and not isinstance(signed_receipt, str):
        return False
    if policy is not None and not _typed(policy, _POLICY_MEMBERS):
        return False
    if keys is None:
        return True
    if not isinstance(keys, dict):
        return False
    for performer in keys.values():
        if performer is None:
            continue
        if not isinstance(performer, dict):
            return False
        if not all(entry is None or _typed(entry, _ENTRY_MEMBERS) for entry in performer.values()):
            return False
    return True


def _decode_object(segment):
    """A base64url segment that must hold one JSON object (header and payload
    policy: last-wins duplicates, non-finite deferred to step 7)."""
    raw = b64url_decode_strict(segment)
    obj = parse_json(raw, dup="last", nonfinite="defer")
    if not isinstance(obj, dict):
        raise _Reject("not an object")
    return raw, obj


def _verify_reason(signed_receipt, keys, policy):
    # 1. malformed
    if signed_receipt is None:
        return "malformed"
    parts = signed_receipt.split(".")
    if len(parts) != 3:
        return "malformed"
    try:
        sig = b64url_decode_strict(parts[2])
        _, header = _decode_object(parts[0])
        if "b64" in header and header["b64"] is not True:
            return "malformed"
        payload_bytes, payload = _decode_object(parts[1])
    except _Reject:
        return "malformed"
    # 2. header_key_material
    if any(m in header for m in _FORBIDDEN_HEADER):
        return "header_key_material"
    # 3. unknown_key
    performer_id, kid = payload.get("performer_id"), header.get("kid")
    if not isinstance(performer_id, str) or not isinstance(kid, str):
        return "unknown_key"
    entry = ((keys or {}).get(performer_id) or {}).get(kid)
    if entry is None:
        return "unknown_key"
    # 4. revoked_key
    if entry.get("status") == "revoked":
        return "revoked_key"
    # 5. alg_not_allowed
    alg = header.get("alg")
    if not isinstance(alg, str) or alg in ("", "none") or alg != entry.get("alg"):
        return "alg_not_allowed"
    if alg not in ALGS:
        return "alg_not_allowed"
    kty, crv, coords, verify_fn = ALGS[alg]
    if entry.get("kty") != kty or entry.get("crv") != crv:
        return "alg_not_allowed"
    # 6. bad_signature: key material goes through the same decoder as the segments
    try:
        material = [b64url_decode_strict(entry.get(c)) for c in coords]
    except _Reject:
        return "bad_signature"
    if any(len(m) != 32 for m in material):
        return "bad_signature"
    if not verify_fn(*material, sig, (parts[0] + "." + parts[1]).encode("ascii")):
        return "bad_signature"
    # 7. non_canonical_payload (a duplicate key collapses at parse, so it always differs here)
    try:
        if jcs(payload) != payload_bytes:
            return "non_canonical_payload"
    except _NotCanonical:
        return "non_canonical_payload"
    # 8. context_mismatch
    policy = policy or {}
    for member, claim in (("expected_binding", "binding"), ("expected_method", "method")):
        expected = policy.get(member)
        if expected is not None and payload.get(claim) != expected:
            return "context_mismatch"
    return "ok"


def verify(signed_receipt, keys=None, policy=None):
    """Verdict dict for one compact JWS: {"reason": ..., "valid": ...}, or
    {"error": "invalid_input"} when an argument has the wrong JSON type."""
    if not _verify_shape(signed_receipt, keys, policy):
        return {"error": "invalid_input"}
    reason = _verify_reason(signed_receipt, keys, policy)
    return {"reason": reason, "valid": reason == "ok"}
