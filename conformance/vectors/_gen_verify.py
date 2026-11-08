#!/usr/bin/env python3
"""Generate JWS `verify` conformance vectors (valid + adversarial).

Fixed TEST keypairs (NOT secrets — deterministic, committed as fixtures). Builds JWS compact
receipts and a registry, then hand-sets the expected verdict per vector by construction.

Run: uv run --with cryptography --with ecdsa --no-project python vectors/_gen_verify.py
"""
import base64
import copy
import hashlib
import json
import pathlib

from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from ecdsa import SigningKey, NIST256p
from ecdsa.util import sigencode_string

OUT = pathlib.Path(__file__).parent


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jcs(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


# ---- fixed test keys (deterministic) ----
ED_SEED = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")            # exactly 32 bytes
assert len(ED_SEED) == 32
ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ED_SEED)
ed_pub = ed_priv.public_key().public_bytes_raw()         # 32 bytes

ED_SEED_OTHER = bytes.fromhex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
assert len(ED_SEED_OTHER) == 32
ed_priv_other = ed25519.Ed25519PrivateKey.from_private_bytes(ED_SEED_OTHER)

EC_D = 0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
ec_priv = ec.derive_private_key(EC_D, ec.SECP256R1())
ec_nums = ec_priv.public_key().public_numbers()
ec_x = ec_nums.x.to_bytes(32, "big")
ec_y = ec_nums.y.to_bytes(32, "big")
# RFC 6979 deterministic ECDSA signer (same secret exponent) — cryptography's
# ECDSA nonce is randomized, which would make regenerated vectors non-reproducible.
ec_sk = SigningKey.from_secret_exponent(EC_D, curve=NIST256p)


def jws_raw(header_bytes: bytes, payload_bytes: bytes, alg: str, *, priv=None, mutate_seg=None) -> str:
    """Build a JWS compact string from ARBITRARY header and payload bytes.

    The signature is computed over the base64url of those exact bytes, so it is
    VALID over whatever the caller passes in (BOM, invalid UTF-8, lone-surrogate
    escapes, odd `b64` members). `mutate_seg` is applied AFTER signing, as a dict
    {segment_index: fn(str) -> str}, to corrupt a segment without touching the
    signature (CR/LF, trailing-bit flips, extra characters).
    """
    h = b64u(header_bytes)
    p = b64u(payload_bytes)
    signing_input = f"{h}.{p}".encode()
    if alg == "none":
        segs = [h, p, ""]
    else:
        if alg == "EdDSA":
            sig = (priv or ed_priv).sign(signing_input)
        elif alg == "ES256":
            # RFC 6979 deterministic nonce; sigencode_string yields JWS raw R||S (64 bytes)
            sig = (priv or ec_sk).sign_deterministic(
                signing_input, hashfunc=hashlib.sha256, sigencode=sigencode_string)
        else:
            raise ValueError(alg)
        segs = [h, p, b64u(sig)]
    for idx, fn in (mutate_seg or {}).items():
        segs[idx] = fn(segs[idx])
    return ".".join(segs)


def jws(header: dict, payload_bytes: bytes, alg: str, priv=None) -> str:
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    return jws_raw(header_bytes, payload_bytes, alg, priv=priv)


def receipt(performer_id: str, binding: str = "mcp", method: str = "mcp:echo") -> dict:
    return {
        "v": "vitni/0.2", "binding": binding, "action_ref": None,
        "performer_id": performer_id, "requester_id": None, "method": method,
        "inputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
        "outputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
        "cost": {"tokens": "10", "usd_micros": "0", "wall_ms": "3", "rail_ref": None},
        "status": "OK", "reason": None, "parent_receipt_hash": None,
        "log_policy": "best_effort", "ts": "2026-05-28T00:00:00Z",
        "nonce": "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",
    }


def reg(status_ed="active", status_ec="active") -> dict:
    return {
        "srv-ed": {"ed-1": {"kty": "OKP", "crv": "Ed25519", "x": b64u(ed_pub),
                            "alg": "EdDSA", "status": status_ed}},
        "srv-ec": {"ec-1": {"kty": "EC", "crv": "P-256", "x": b64u(ec_x), "y": b64u(ec_y),
                            "alg": "ES256", "status": status_ec}},
    }


def reg_with(*, ed=None, ec=None, status_ed="active", status_ec="active", extra=None) -> dict:
    """Deep copy of reg() with per-key overrides.

    `ed` / `ec` are dicts merged into the srv-ed/ed-1 and srv-ec/ec-1 entries; a
    value of DELETE removes that member. `extra` is merged into the top level.
    """
    out = copy.deepcopy(reg(status_ed, status_ec))
    for entry, patch in ((out["srv-ed"]["ed-1"], ed), (out["srv-ec"]["ec-1"], ec)):
        for k, v in (patch or {}).items():
            if v is DELETE:
                entry.pop(k, None)
            else:
                entry[k] = v
    out.update(extra or {})
    return out


DELETE = object()  # sentinel for reg_with: remove this member

# builder self-checks (run on every regeneration)
_h = b'{"alg":"EdDSA","kid":"ed-1"}'
assert jws_raw(_h, b"{}", "EdDSA") == jws({"alg": "EdDSA", "kid": "ed-1"}, b"{}", "EdDSA")
assert jws_raw(_h, b"{}", "EdDSA", mutate_seg={2: lambda t: t + "A"}).split(".")[2] == \
    jws_raw(_h, b"{}", "EdDSA").split(".")[2] + "A"
assert reg_with(ed={"kty": "EC"})["srv-ed"]["ed-1"]["kty"] == "EC" and reg()["srv-ed"]["ed-1"]["kty"] == "OKP"
assert "kty" not in reg_with(ed={"kty": DELETE})["srv-ed"]["ed-1"]


NO_POLICY = {"expected_binding": None, "expected_method": None}


def write(fname, name, signed, keys, policy, valid, reason):
    (OUT / fname).write_text(json.dumps({
        "name": name, "command": "verify",
        "input": {"signed_receipt": signed, "keys": keys, "policy": policy},
        "anchor": {"valid": valid, "reason": reason},
    }) + "\n")


ed_payload = jcs(receipt("srv-ed")).encode()
ec_payload = jcs(receipt("srv-ec")).encode()

# 1. valid Ed25519
write("verify-valid-ed25519.json", "verify/valid-ed25519",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA"),
      reg(), NO_POLICY, True, "ok")

# 2. valid ES256
write("verify-valid-es256.json", "verify/valid-es256",
      jws({"alg": "ES256", "kid": "ec-1"}, ec_payload, "ES256"),
      reg(), NO_POLICY, True, "ok")

# 3. alg:none
write("verify-alg-none.json", "verify/alg-none",
      jws({"alg": "none", "kid": "ed-1"}, ed_payload, "none"),
      reg(), NO_POLICY, False, "alg_not_allowed")

# 4. alg substitution: header says ES256 but key ed-1 is EdDSA
write("verify-alg-substitution.json", "verify/alg-substitution",
      jws({"alg": "ES256", "kid": "ed-1"}, ed_payload, "EdDSA"),  # signed Ed but header lies
      reg(), NO_POLICY, False, "alg_not_allowed")

# 5. jwk header injection (otherwise valid)
write("verify-jwk-header-injection.json", "verify/jwk-header-injection",
      jws({"alg": "EdDSA", "kid": "ed-1", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(ed_pub)}},
          ed_payload, "EdDSA"),
      reg(), NO_POLICY, False, "header_key_material")

# 6. bad signature: keep header+payload valid & canonical, corrupt the SIGNATURE.
#    This tests bad_signature cleanly (step 6) without tripping malformed (step 1).
good = jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA")
h, p, s = good.split(".")
sig_bytes = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
sig_bytes[0] ^= 0xFF  # flip one byte of the signature
write("verify-bad-signature.json", "verify/bad-signature",
      f"{h}.{p}.{b64u(bytes(sig_bytes))}", reg(), NO_POLICY, False, "bad_signature")

# 6b. malformed: payload is valid base64url but NOT valid JSON -> step 1 malformed
#     (signature is over the non-JSON bytes so the JWS is structurally well-formed)
write("verify-malformed-payload.json", "verify/malformed-payload",
      jws({"alg": "EdDSA", "kid": "ed-1"}, b"this is not json", "EdDSA"),
      reg(), NO_POLICY, False, "malformed")

# 7. non-canonical but validly-signed payload (unsorted keys + spaces)
noncanon = json.dumps(receipt("srv-ed"), sort_keys=False, indent=1).encode()
write("verify-non-canonical-payload.json", "verify/non-canonical-payload",
      jws({"alg": "EdDSA", "kid": "ed-1"}, noncanon, "EdDSA"),
      reg(), NO_POLICY, False, "non_canonical_payload")

# 8. unknown kid
write("verify-unknown-kid.json", "verify/unknown-kid",
      jws({"alg": "EdDSA", "kid": "ed-999"}, ed_payload, "EdDSA"),
      reg(), NO_POLICY, False, "unknown_key")

# 9. revoked key (valid sig, but registry marks revoked)
write("verify-revoked-key.json", "verify/revoked-key",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA"),
      reg(status_ed="revoked"), NO_POLICY, False, "revoked_key")

# 10. context mismatch (valid receipt binding mcp, policy expects a2a)
write("verify-context-mismatch.json", "verify/context-mismatch",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA"),
      reg(), {"expected_binding": "a2a", "expected_method": None},
      False, "context_mismatch")

# 11. wrong key, right alg (signed by a different Ed key than registry's ed-1)
write("verify-wrong-key.json", "verify/wrong-key",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA", priv=ed_priv_other),
      reg(), NO_POLICY, False, "bad_signature")

# 12. sign/ed25519 (previously hand-authored; now generated)
#     Deterministic key: bytes 0x01..0x20 == base64 "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
SIGN_SEED = bytes(range(1, 33))
sign_priv = ed25519.Ed25519PrivateKey.from_private_bytes(SIGN_SEED)
sign_receipt = receipt("srv-ed")
sign_payload = jcs(sign_receipt).encode()
signed_sign_vector = jws({"alg": "EdDSA", "kid": "ed-1"}, sign_payload, "EdDSA", priv=sign_priv)
(OUT / "sign-ed25519.json").write_text(json.dumps({
    "name": "sign/ed25519", "command": "sign",
    "input": {"receipt": sign_receipt, "kid": "ed-1",
              "private_key_b64": base64.b64encode(SIGN_SEED).decode()},
    "anchor": {"signed_receipt": signed_sign_vector},
}) + "\n")

# 13. local binding, valid
r_local = receipt("srv-ed", binding="local", method="local:daimon.serialize")
local_payload = jcs(r_local).encode()
write("verify-local-valid.json", "verify/local-valid",
      jws({"alg": "EdDSA", "kid": "ed-1"}, local_payload, "EdDSA"),
      reg(), NO_POLICY, True, "ok")

# 14. local receipt presented as mcp -> context_mismatch
write("verify-local-context-mismatch.json", "verify/local-context-mismatch",
      jws({"alg": "EdDSA", "kid": "ed-1"}, local_payload, "EdDSA"),
      reg(), {"expected_binding": "mcp", "expected_method": None},
      False, "context_mismatch")

# 14b. policy expects a method the receipt does not carry -> context_mismatch
#      (the expected_binding arm is vector 10; this is the expected_method arm)
write("verify-method-mismatch.json", "verify/method-mismatch",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA"),
      reg(), {"expected_binding": None, "expected_method": "mcp:other"},
      False, "context_mismatch")

# 14c. both constraints present and both satisfied -> ok
write("verify-policy-match.json", "verify/policy-match",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA"),
      reg(), {"expected_binding": "mcp", "expected_method": "mcp:echo"},
      True, "ok")

# 14d. the performer is not a registry key at all (kid ed-1 exists under srv-ed,
#      but the receipt names srv-stranger) -> unknown_key
write("verify-unknown-performer.json", "verify/unknown-performer",
      jws({"alg": "EdDSA", "kid": "ed-1"}, jcs(receipt("srv-stranger")).encode(), "EdDSA"),
      reg(), NO_POLICY, False, "unknown_key")

# 14e. a header with no kid cannot resolve a key -> unknown_key (an absent kid
#      is not an empty one: the signature here is valid over the header as sent)
write("verify-header-no-kid.json", "verify/header-no-kid",
      jws({"alg": "EdDSA"}, ed_payload, "EdDSA"),
      reg(), NO_POLICY, False, "unknown_key")

# 15. ext present, still valid (ext never affects verification)
r_ext = receipt("srv-ed")
r_ext["ext"] = {"dev.daimon/prompt_version": "3"}
ext_payload = jcs(r_ext).encode()
write("verify-ext-valid.json", "verify/ext-valid",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ext_payload, "EdDSA"),
      reg(), NO_POLICY, True, "ok")

# ---------------------------------------------------------------------------
# PR 0a, batch 2: ONE strict base64url decoder for JWS segments and key material.
# Every vector below carries a signature that is valid over the UNMUTATED
# receipt; the mutation is applied after signing, so the verdict is decided by
# the segment/key-material rule and not by anything else in the receipt.
# ---------------------------------------------------------------------------
B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def insert_at(i: int, ch: str):
    return lambda t: t[:i] + ch + t[i:]


def flip_trailing_bit(t: str) -> str:
    """Set the lowest bit of the last character. For a canonical segment whose
    byte length is not a multiple of 3 that bit is a trailing (padding) bit that
    is zero in the canonical encoding, so the result decodes to the SAME bytes
    under a lenient decoder and is non-canonical under a strict one."""
    idx = B64U.index(t[-1])
    assert idx & 1 == 0, "last char already has a non-zero low bit"
    return t[:-1] + B64U[idx | 1]


def to_len_1_mod_4(t: str) -> str:
    return t + "A" * (((1 - len(t)) % 4) or 4)


MALFORMED = (False, "malformed")
BAD_SIG = (False, "bad_signature")
ED_HDR = {"alg": "EdDSA", "kid": "ed-1"}
# header/payload variants whose byte length is NOT a multiple of 3, so their
# base64url form has trailing bits (trailing ASCII space is valid JSON text)
ED_HDR_PAD = json.dumps(ED_HDR, separators=(",", ":"), sort_keys=True).encode() + b" "
ED_PAYLOAD_PAD = ed_payload + b" " if len(ed_payload) % 3 == 0 else ed_payload
assert len(ED_HDR_PAD) % 3 != 0 and len(ED_PAYLOAD_PAD) % 3 != 0


def seg_vec(fname, name, mutate_seg, verdict, hdr=None, payload=None):
    signed = jws_raw(hdr or json.dumps(ED_HDR, separators=(",", ":"), sort_keys=True).encode(),
                     payload or ed_payload, "EdDSA", mutate_seg=mutate_seg)
    write(fname, name, signed, reg(), NO_POLICY, *verdict)


# D1: CR/LF inside a segment (Go's RawURLEncoding silently skips them)
seg_vec("verify-sig-lf-inside.json", "verify/sig-lf-inside", {2: insert_at(10, "\n")}, MALFORMED)
seg_vec("verify-sig-cr-inside.json", "verify/sig-cr-inside", {2: insert_at(10, "\r")}, MALFORMED)
seg_vec("verify-header-seg-lf.json", "verify/header-seg-lf", {0: insert_at(10, "\n")}, MALFORMED)
seg_vec("verify-payload-seg-lf.json", "verify/payload-seg-lf", {1: insert_at(10, "\n")}, MALFORMED)
# D2: segment length = 1 mod 4 is never valid base64url
seg_vec("verify-segment-len-1-mod-4.json", "verify/segment-len-1-mod-4", {2: to_len_1_mod_4}, MALFORMED)
# D3/D3b: non-zero trailing bits are rejected (one canonical encoding per byte string)
seg_vec("verify-sig-trailing-bits.json", "verify/sig-trailing-bits", {2: flip_trailing_bit}, MALFORMED)
seg_vec("verify-header-trailing-bits.json", "verify/header-trailing-bits", {0: flip_trailing_bit},
        MALFORMED, hdr=ED_HDR_PAD)
seg_vec("verify-payload-trailing-bits.json", "verify/payload-trailing-bits", {1: flip_trailing_bit},
        MALFORMED, payload=ED_PAYLOAD_PAD)
# S0.46 pins: already identical in Go and TS today, pinned for any third verifier
seg_vec("verify-segments-four.json", "verify/segments-four", {2: lambda t: t + ".AAAA"}, MALFORMED)
seg_vec("verify-segment-padded.json", "verify/segment-padded", {0: lambda t: t + "="}, MALFORMED)
seg_vec("verify-segment-std-alphabet.json", "verify/segment-std-alphabet",
        {2: lambda t: t[:5] + "/" + t[6:]}, MALFORMED)

# Key material (R0.2): x/y go through the same strict decoder. Failure here is
# bad_signature (a key-material problem), while the same decoder failing on a JWS
# segment is malformed: the call site chooses the code, the decoder is shared.
ed_receipt = jws({"alg": "EdDSA", "kid": "ed-1"}, ed_payload, "EdDSA")
ec_receipt = jws({"alg": "ES256", "kid": "ec-1"}, ec_payload, "ES256")
ed_x = b64u(ed_pub)
ec_xs, ec_ys = b64u(ec_x), b64u(ec_y)


def std_alphabet(t: str) -> str:
    out = t.replace("-", "+").replace("_", "/")
    assert out != t, "key has no - or _ to convert; pick another test key"
    return out


def key_vec(fname, name, signed, keys):
    write(fname, name, signed, keys, NO_POLICY, *BAD_SIG)


key_vec("verify-key-eddsa-x-padded.json", "verify/key-eddsa-x-padded", ed_receipt,
        reg_with(ed={"x": ed_x + "="}))
key_vec("verify-key-eddsa-x-std-alphabet.json", "verify/key-eddsa-x-std-alphabet", ed_receipt,
        reg_with(ed={"x": std_alphabet(ed_x)}))
key_vec("verify-key-eddsa-x-newline.json", "verify/key-eddsa-x-newline", ed_receipt,
        reg_with(ed={"x": ed_x[:20] + "\n" + ed_x[20:]}))
key_vec("verify-key-eddsa-x-trailing-bits.json", "verify/key-eddsa-x-trailing-bits", ed_receipt,
        reg_with(ed={"x": flip_trailing_bit(ed_x)}))
key_vec("verify-key-es256-x-33-bytes.json", "verify/key-es256-x-33-bytes", ec_receipt,
        reg_with(ec={"x": b64u(b"\x00" + ec_x)}))
key_vec("verify-key-es256-y-padded.json", "verify/key-es256-y-padded", ec_receipt,
        reg_with(ec={"y": ec_ys + "="}))
key_vec("verify-key-es256-x-std-alphabet.json", "verify/key-es256-x-std-alphabet", ec_receipt,
        reg_with(ec={"x": std_alphabet(ec_xs)}))
key_vec("verify-key-es256-offcurve.json", "verify/key-es256-offcurve", ec_receipt,
        reg_with(ec={"y": b64u((int.from_bytes(ec_y, "big") + 1).to_bytes(32, "big"))}))

# ---------------------------------------------------------------------------
# PR 0a, batch 3: the algorithm table owns {alg -> kty, crv}. A registry key is
# usable only when its kty/crv are the ones its alg requires (R0.1, N9, N11).
# All receipts carry a VALID signature, so alg_not_allowed is decided by the
# key-type rule and not masked by bad_signature.
# ---------------------------------------------------------------------------
NOT_ALLOWED = (False, "alg_not_allowed")


def bind_vec(fname, name, signed, keys, verdict=NOT_ALLOWED):
    write(fname, name, signed, keys, NO_POLICY, *verdict)


bind_vec("verify-key-es256-kty-okp.json", "verify/key-es256-kty-okp", ec_receipt,
         reg_with(ec={"kty": "OKP"}))
bind_vec("verify-key-es256-crv-p384.json", "verify/key-es256-crv-p384", ec_receipt,
         reg_with(ec={"crv": "P-384"}))
bind_vec("verify-key-eddsa-kty-ec.json", "verify/key-eddsa-kty-ec", ed_receipt,
         reg_with(ed={"kty": "EC"}))
bind_vec("verify-key-eddsa-crv-ed448.json", "verify/key-eddsa-crv-ed448", ed_receipt,
         reg_with(ed={"crv": "Ed448"}))
bind_vec("verify-key-eddsa-kty-missing.json", "verify/key-eddsa-kty-missing", ed_receipt,
         reg_with(ed={"kty": DELETE}))
bind_vec("verify-key-eddsa-crv-null.json", "verify/key-eddsa-crv-null", ed_receipt,
         reg_with(ed={"crv": None}))
# N11: an alg outside the table is alg_not_allowed even when header and registry
# agree on it (the signature is junk and irrelevant: the alg check comes first)
rs256 = ".".join([b64u(b'{"alg":"RS256","kid":"ed-1"}'), b64u(ed_payload), b64u(b"junk" * 16)])
bind_vec("verify-key-alg-rs256.json", "verify/key-alg-rs256", rs256,
         reg_with(ed={"alg": "RS256"}))
# ordering guards: revoked (step 4) beats the key-type rule; the header/registry
# alg-equality rule and the key-type rule give the same code
bind_vec("verify-key-revoked-and-mismatched.json", "verify/key-revoked-and-mismatched", ed_receipt,
         reg_with(ed={"kty": "EC"}, status_ed="revoked"), (False, "revoked_key"))
bind_vec("verify-key-alg-header-mismatch-and-bad-kty.json",
         "verify/key-alg-header-mismatch-and-bad-kty",
         jws({"alg": "ES256", "kid": "ed-1"}, ed_payload, "EdDSA"),
         reg_with(ed={"kty": "EC"}))

# ---------------------------------------------------------------------------
# PR 0a, batch 4: strict header/payload text (R0.4), the `b64` header (R0.5).
# jws_raw signs over the exact mutated bytes, so every signature below is VALID
# and the verdict is decided by the text rule under test.
# Policy (design 3.1): both texts are strict UTF-8, no BOM, no lone-surrogate
# escape, exactly one object, depth <= 128, all violations are `malformed` at
# step 1. Duplicate header keys are last-wins; non-finite numbers are accepted
# in the header (never serialized) and deferred in the payload (step 7 fails).
# ---------------------------------------------------------------------------
OK = (True, "ok")
NON_CANON = (False, "non_canonical_payload")
ED_HDR_BYTES = json.dumps(ED_HDR, separators=(",", ":"), sort_keys=True).encode()
BOM = b"\xef\xbb\xbf"


def ext_payload(raw_value: bytes) -> bytes:
    """Canonical receipt payload whose ext.e is the given RAW JSON value bytes
    (including quotes), spliced in after canonicalization."""
    r = receipt("srv-ed")
    r["ext"] = {"e": "PLACEHOLDER"}
    out = jcs(r).encode().replace(b'"PLACEHOLDER"', raw_value)
    assert raw_value in out
    return out


def text_vec(fname, name, hdr, payload, verdict):
    write(fname, name, jws_raw(hdr, payload, "EdDSA"), reg(), NO_POLICY, *verdict)


# payload text
text_vec("verify-payload-lone-surrogate.json", "verify/payload-lone-surrogate",
         ED_HDR_BYTES, ext_payload(b'"\\ud800"'), MALFORMED)
text_vec("verify-payload-lone-low-surrogate.json", "verify/payload-lone-low-surrogate",
         ED_HDR_BYTES, ext_payload(b'"\\udc00"'), MALFORMED)
text_vec("verify-payload-bom.json", "verify/payload-bom",
         ED_HDR_BYTES, BOM + ed_payload, MALFORMED)
text_vec("verify-payload-invalid-utf8.json", "verify/payload-invalid-utf8",
         ED_HDR_BYTES, ext_payload(b'"\xff"'), MALFORMED)
# a valid surrogate PAIR escape is well-formed text, so it is NOT malformed; it is
# simply not canonical (JCS emits the raw character)
text_vec("verify-payload-surrogate-pair-escape.json", "verify/payload-surrogate-pair-escape",
         ED_HDR_BYTES, ext_payload(b'"\\ud83d\\ude00"'), NON_CANON)
text_vec("verify-payload-nonbmp-raw.json", "verify/payload-nonbmp-raw",
         ED_HDR_BYTES, ext_payload('"\U0001F600"'.encode()), OK)
# duplicate payload key: last-wins at parse, but the re-serialization differs
# from the transmitted bytes, so step 7 reports non_canonical_payload
assert ed_payload.endswith(b',"v":"vitni/0.2"}')
text_vec("verify-payload-duplicate-key.json", "verify/payload-duplicate-key",
         ED_HDR_BYTES, ed_payload[:-1] + b',"v":"vitni/0.2"}', NON_CANON)
# non-finite in the payload is deferred to step 7 (it can never be canonical)
nf = receipt("srv-ed")
nf["ext"] = {"n": 7}
nf_payload = jcs(nf).encode().replace(b'"n":7', b'"n":1e400')
assert b"1e400" in nf_payload
text_vec("verify-payload-nonfinite-defer.json", "verify/payload-nonfinite-defer",
         ED_HDR_BYTES, nf_payload, NON_CANON)

# header text
text_vec("verify-header-bom.json", "verify/header-bom",
         BOM + ED_HDR_BYTES, ed_payload, MALFORMED)
text_vec("verify-header-invalid-utf8.json", "verify/header-invalid-utf8",
         b'{"alg":"EdDSA","kid":"ed-1","x":"\xff"}', ed_payload, MALFORMED)
text_vec("verify-header-lone-surrogate.json", "verify/header-lone-surrogate",
         b'{"alg":"EdDSA","kid":"ed-1","x":"\\ud800"}', ed_payload, MALFORMED)
text_vec("verify-header-duplicate-key-last-wins.json", "verify/header-duplicate-key-last-wins",
         b'{"alg":"EdDSA","kid":"zzz","kid":"ed-1"}', ed_payload, OK)
# the header is never serialized, so a non-finite number in an ignored member is fine
text_vec("verify-header-nonfinite-ignored.json", "verify/header-nonfinite-ignored",
         b'{"alg":"EdDSA","kid":"ed-1","x":1e400}', ed_payload, OK)

# b64 header member (RFC 7797): true is equivalent to absent; anything else is malformed
for suffix, raw, verdict in (("false", b"false", MALFORMED), ("true", b"true", OK),
                             ("string", b'"false"', MALFORMED), ("null", b"null", MALFORMED)):
    text_vec(f"verify-header-b64-{suffix}.json", f"verify/header-b64-{suffix}",
             b'{"alg":"EdDSA","b64":' + raw + b',"kid":"ed-1"}', ed_payload, verdict)

# Nesting depth limit (ADR-6, owner Q-D9): the payload object is depth 1, each
# nested object or array adds one. Depth 128 is accepted, 129 is malformed.
# ext (depth 2) holds 126 or 127 nested arrays.
text_vec("verify-payload-depth-128.json", "verify/payload-depth-128",
         ED_HDR_BYTES, ext_payload(b"[" * 126 + b"]" * 126), OK)
text_vec("verify-payload-depth-129.json", "verify/payload-depth-129",
         ED_HDR_BYTES, ext_payload(b"[" * 127 + b"]" * 127), MALFORMED)

# header or payload that is valid JSON but not an object (R0.4: "exactly one
# object"). `null` is the easy one to miss: Go's json.Unmarshal into a map
# accepts it and leaves a nil map.
text_vec("verify-header-null.json", "verify/header-null", b"null", ed_payload, MALFORMED)
text_vec("verify-payload-null.json", "verify/payload-null", ED_HDR_BYTES, b"null", MALFORMED)
text_vec("verify-header-array.json", "verify/header-array", b"[]", ed_payload, MALFORMED)

# ---------------------------------------------------------------------------
# PR 0a, batch 5a: existing PARSE and signature-shape rules, pinned so that a
# third verifier cannot choose a lenient default. GREEN on Go and TS today.
# ---------------------------------------------------------------------------
text_vec("verify-payload-array.json", "verify/payload-array", ED_HDR_BYTES, b"[]", MALFORMED)
text_vec("verify-kid-non-string.json", "verify/kid-non-string",
         b'{"alg":"EdDSA","kid":5}', ed_payload, (False, "unknown_key"))
perf5 = receipt("srv-ed")
perf5["performer_id"] = 5
text_vec("verify-performer-non-string.json", "verify/performer-non-string",
         ED_HDR_BYTES, jcs(perf5).encode(), (False, "unknown_key"))
# only the exact string "revoked" revokes; anything else counts as active
write("verify-status-odd-is-active.json", "verify/status-odd-is-active", ed_receipt,
      reg_with(ed={"status": "Revoked"}), NO_POLICY, *OK)

EC_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ED_L = 2**252 + 27742317777372353535851937790883648493


def sig_edit(fn):
    """mutate_seg for the signature segment: decode, edit the raw bytes, re-encode."""
    def edit(seg):
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        return b64u(fn(raw))
    return edit


def es_rs(raw):
    return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")


def es_pack(r, s):
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ec_vec(fname, name, fn, verdict):
    signed = jws_raw(json.dumps({"alg": "ES256", "kid": "ec-1"}, separators=(",", ":"),
                                sort_keys=True).encode(), ec_payload, "ES256",
                     mutate_seg={2: sig_edit(fn)})
    write(fname, name, signed, reg(), NO_POLICY, *verdict)


def high_s(raw):
    r, s = es_rs(raw)
    return es_pack(r, EC_N - s if s <= EC_N // 2 else s)


# ES256: a high-S signature is accepted (no malleability rule in v1); r=s=0, r=n,
# s=0 and any length other than 64 bytes are bad_signature
assert es_rs(high_s(base64.urlsafe_b64decode(ec_receipt.split(".")[2] + "==")))[1] > EC_N // 2
ec_vec("verify-es256-high-s.json", "verify/es256-high-s", high_s, OK)
ec_vec("verify-es256-r-s-zero.json", "verify/es256-r-s-zero", lambda raw: bytes(64), BAD_SIG)
ec_vec("verify-es256-r-equals-n.json", "verify/es256-r-equals-n",
       lambda raw: es_pack(EC_N, es_rs(raw)[1]), BAD_SIG)
ec_vec("verify-es256-s-zero.json", "verify/es256-s-zero",
       lambda raw: es_pack(es_rs(raw)[0], 0), BAD_SIG)
ec_vec("verify-es256-sig-63.json", "verify/es256-sig-63", lambda raw: raw[:-1], BAD_SIG)
ec_vec("verify-es256-sig-65.json", "verify/es256-sig-65", lambda raw: raw + b"\x00", BAD_SIG)


def ed_vec(fname, name, fn, verdict):
    signed = jws_raw(ED_HDR_BYTES, ed_payload, "EdDSA", mutate_seg={2: sig_edit(fn)})
    write(fname, name, signed, reg(), NO_POLICY, *verdict)


def s_plus_l(raw):
    s_val = int.from_bytes(raw[32:], "little")
    assert s_val < ED_L
    return raw[:32] + (s_val + ED_L).to_bytes(32, "little")


# Ed25519: S >= L is rejected (S+L would verify under a cofactored or lenient check
# that reduces S), and a 63-byte signature is bad_signature
ed_vec("verify-eddsa-s-plus-l.json", "verify/eddsa-s-plus-l", s_plus_l, BAD_SIG)
ed_vec("verify-eddsa-sig-63.json", "verify/eddsa-sig-63", lambda raw: raw[:-1], BAD_SIG)

# ---------------------------------------------------------------------------
# PR 0a, batch 5b: Ed25519 small-order and non-canonical points. Go and TS agree
# on every combination today; the vectors pin the verdicts so a third verifier
# cannot add identity/small-order rejection or a stricter decode. All use
# S = 0 and a literal A and R: no private key exists for these points.
# The rule pinned (cofactorless, R compared by its 32-byte encoding):
#   accept iff encode([S]B - [k]A) == R_bytes, k = SHA512(R || A || msg) mod L.
# ---------------------------------------------------------------------------
IDENT = bytes([1]) + bytes(31)                       # y=1, x=0 (neutral element)
IDENT_SIGNBIT = bytes([1]) + bytes(30) + bytes([0x80])  # same point, sign bit set
Y_P_PLUS_1 = bytes([0xEE]) + b"\xff" * 30 + bytes([0x7F])  # y = p+1 (non-canonical y=1)
ORDER2_SIGNBIT = bytes([0xEC]) + b"\xff" * 30 + bytes([0xFF])  # y = p-1 (order 2), sign bit set
ORDER8_A = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
ORDER8_B = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")


def ed_k(r_bytes, a_bytes, signing_input):
    return int.from_bytes(hashlib.sha512(r_bytes + a_bytes + signing_input).digest(), "little") % ED_L


def order8_self_equal_ok(a_bytes, signing_input):
    """R = A, S = 0: [0]B == A + [k]A iff (k+1) * A is the identity iff (k+1) % 8 == 0
    for an order-8 A (k is already reduced mod L, as every verifier does)."""
    return (ed_k(a_bytes, a_bytes, signing_input) + 1) % 8 == 0


def ed_edge_signing_input(i):
    payload = jcs({**receipt("srv-ed"), "ext": {"e": i}}).encode()
    return payload, f"{b64u(ED_HDR_BYTES)}.{b64u(payload)}".encode()


# Payload bytes are searched ONCE (smallest i) so the pinned verdicts are the ones the
# group equation yields: order8-b R=A verifies (ok), order8-a R=A does not
# (bad_signature), and for the order-2 key (R = identity) k is even so [k]A is the
# identity and the signature verifies. The verdict set stays {ok, bad_signature}.
for _i in range(1000):
    _payload, _si = ed_edge_signing_input(_i)
    if (order8_self_equal_ok(ORDER8_B, _si) and not order8_self_equal_ok(ORDER8_A, _si)
            and ed_k(IDENT, ORDER2_SIGNBIT, _si) % 2 == 0):
        ED_EDGE_PAYLOAD, ED_EDGE_SI = _payload, _si
        break
else:
    raise SystemExit("no payload found for the order-8 pair")


def edge_vec(fname, name, a_bytes, r_bytes, verdict):
    signed = ".".join([b64u(ED_HDR_BYTES), b64u(ED_EDGE_PAYLOAD), b64u(r_bytes + bytes(32))])
    write(fname, name, signed, reg_with(ed={"x": b64u(a_bytes)}), NO_POLICY, *verdict)


edge_vec("verify-ed-smallorder-identity.json", "verify/ed-smallorder-identity", IDENT, IDENT, OK)
edge_vec("verify-ed-identity-signbit.json", "verify/ed-identity-signbit", IDENT_SIGNBIT, IDENT, OK)
edge_vec("verify-ed-identity-noncanonical-y.json", "verify/ed-identity-noncanonical-y",
         Y_P_PLUS_1, IDENT, OK)
edge_vec("verify-ed-order2-signbit.json", "verify/ed-order2-signbit", ORDER2_SIGNBIT, IDENT, OK)
edge_vec("verify-ed-r-noncanonical.json", "verify/ed-r-noncanonical", IDENT, Y_P_PLUS_1, BAD_SIG)
edge_vec("verify-ed-order8-a-r-eq-a.json", "verify/ed-order8-a-r-eq-a", ORDER8_A, ORDER8_A, BAD_SIG)
edge_vec("verify-ed-order8-b-r-eq-a.json", "verify/ed-order8-b-r-eq-a", ORDER8_B, ORDER8_B, OK)

print("wrote verify vectors:")
for p in sorted(OUT.glob("verify-*.json")):
    print(" ", p.name)

# ---------------------------------------------------------------------------
# #69 follow-ups. (1) Surrogate escapes are case-insensitive hex: the uppercase
# lone and high-high forms are malformed, the uppercase valid pair is merely
# non-canonical (same as lowercase). (2) An Ed25519 registry key whose 32 bytes
# are not a curve point (y = 2 has no square root) is a key-material problem:
# bad_signature in every implementation, never a crash and never a pass.
# ---------------------------------------------------------------------------
text_vec("verify-payload-lone-surrogate-upper.json", "verify/payload-lone-surrogate-uppercase",
         ED_HDR_BYTES, ext_payload(b'"\\uD800"'), MALFORMED)
text_vec("verify-payload-high-then-high-surrogate.json", "verify/payload-high-then-high-surrogate",
         ED_HDR_BYTES, ext_payload(b'"\\uD800\\uD800"'), MALFORMED)
text_vec("verify-payload-surrogate-pair-escape-upper.json",
         "verify/payload-surrogate-pair-escape-uppercase",
         ED_HDR_BYTES, ext_payload(b'"\\uD83D\\uDE00"'), NON_CANON)

ED_OFFCURVE_X = b64u(b"\x02" + b"\x00" * 31)
assert ED_OFFCURVE_X == "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
key_vec("verify-key-eddsa-offcurve.json", "verify/key-eddsa-offcurve", ed_receipt,
        reg_with(ed={"x": ED_OFFCURVE_X}))
