#!/usr/bin/env python3
"""Generate JWS `verify` conformance vectors (valid + adversarial).

Fixed TEST keypairs (NOT secrets — deterministic, committed as fixtures). Builds JWS compact
receipts and a registry, then hand-sets the expected verdict per vector by construction.

Run: uv run --with cryptography --with ecdsa --no-project python vectors/_gen_verify.py
"""
import base64
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


def jws(header: dict, payload_bytes: bytes, alg: str, priv=None) -> str:
    h = b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p = b64u(payload_bytes)
    signing_input = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    if alg == "EdDSA":
        sig = (priv or ed_priv).sign(signing_input)
    elif alg == "ES256":
        # RFC 6979 deterministic nonce; sigencode_string yields JWS raw R||S (64 bytes)
        sig = (priv or ec_sk).sign_deterministic(
            signing_input, hashfunc=hashlib.sha256, sigencode=sigencode_string)
    else:
        raise ValueError(alg)
    return f"{h}.{p}.{b64u(sig)}"


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

# 15. ext present, still valid (ext never affects verification)
r_ext = receipt("srv-ed")
r_ext["ext"] = {"dev.daimon/prompt_version": "3"}
ext_payload = jcs(r_ext).encode()
write("verify-ext-valid.json", "verify/ext-valid",
      jws({"alg": "EdDSA", "kid": "ed-1"}, ext_payload, "EdDSA"),
      reg(), NO_POLICY, True, "ok")

print("wrote verify vectors:")
for p in sorted(OUT.glob("verify-*.json")):
    print(" ", p.name)
