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
