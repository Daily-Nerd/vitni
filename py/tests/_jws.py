"""Test-only signer and receipt builder (the verifier under test never signs).
Ed25519 signing is RFC 8032 section 5.1.6 on top of the verifier's own curve
arithmetic, which the RFC vectors and Wycheproof pin independently."""
import base64
import hashlib
import json

from . import _paths  # noqa: F401
import vitni_verify as V

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 TEST 1
PERFORMER = "srv-test"
KID = "k-1"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def ed_public(seed=SEED):
    a = _clamp(seed)
    return V._ed_encode(V._ed_mul(a, V._ED_B))


def _clamp(seed):
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(h, "little")


def ed_sign(msg, seed=SEED):
    h = hashlib.sha512(seed).digest()
    a = _clamp(seed)
    pub = ed_public(seed)
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % V._L
    big_r = V._ed_encode(V._ed_mul(r, V._ED_B))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % V._L
    return big_r + ((r + k * a) % V._L).to_bytes(32, "little")


def payload_dict(**extra):
    p = {"binding": "mcp", "method": "mcp:echo", "performer_id": PERFORMER, "v": "vitni/0.2"}
    p.update(extra)
    return p


def registry(**overrides):
    entry = {"kty": "OKP", "crv": "Ed25519", "x": b64u(ed_public()), "alg": "EdDSA", "status": "active"}
    entry.update(overrides)
    return {PERFORMER: {KID: entry}}


def jws(header=None, payload_bytes=None, sign=True):
    """Compact JWS signed (valid over the exact segments) unless sign=False."""
    header = {"alg": "EdDSA", "kid": KID} if header is None else header
    hb = header if isinstance(header, bytes) else json.dumps(header, separators=(",", ":")).encode("utf-8")
    pb = V.jcs(payload_dict()) if payload_bytes is None else payload_bytes
    signing_input = (b64u(hb) + "." + b64u(pb)).encode("ascii")
    sig = ed_sign(signing_input) if sign else bytes(64)
    return signing_input.decode("ascii") + "." + b64u(sig)
