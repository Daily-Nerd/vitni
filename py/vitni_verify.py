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
