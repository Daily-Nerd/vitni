#!/usr/bin/env python3
"""Generate `verify-chain` conformance vectors (valid chains + splice attacks).

Reuses the same fixed TEST keypairs as _gen_verify.py. Builds real multi-hop signed
receipt chains and sets the expected verdict per vector by construction.

Run: uv run --with cryptography --no-project python vectors/_gen_chain.py
"""
import base64
import hashlib
import json
import pathlib

from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes

OUT = pathlib.Path(__file__).parent


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jcs(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def hashstr(content: bytes) -> str:
    return "u" + b64u(bytes([0x12, 0x20]) + hashlib.sha256(content).digest())


# fixed test keys (identical to _gen_verify.py)
ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
ed_pub = ed_priv.public_key().public_bytes_raw()
EC_D = 0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
ec_priv = ec.derive_private_key(EC_D, ec.SECP256R1())
_n = ec_priv.public_key().public_numbers()
ec_x, ec_y = _n.x.to_bytes(32, "big"), _n.y.to_bytes(32, "big")

REGISTRY = {
    "srv-ed": {"ed-1": {"kty": "OKP", "crv": "Ed25519", "x": b64u(ed_pub), "alg": "EdDSA", "status": "active"}},
    "srv-ec": {"ec-1": {"kty": "EC", "crv": "P-256", "x": b64u(ec_x), "y": b64u(ec_y), "alg": "ES256", "status": "active"}},
}
SIGNERS = {"srv-ed": ("EdDSA", "ed-1"), "srv-ec": ("ES256", "ec-1")}
NO_POLICY = {"expected_binding": None, "expected_method": None}


def sign(performer_id, payload_bytes):
    alg, kid = SIGNERS[performer_id]
    h = b64u(json.dumps({"alg": alg, "kid": kid}, separators=(",", ":"), sort_keys=True).encode())
    p = b64u(payload_bytes)
    si = f"{h}.{p}".encode()
    if alg == "EdDSA":
        sig = ed_priv.sign(si)
    else:
        der = ec_priv.sign(si, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{h}.{p}.{b64u(sig)}", sig


def receipt(performer_id, method, parent_hash, parent_perf):
    return {
        "v": "vitni/0.2", "binding": "mcp", "action_ref": None,
        "performer_id": performer_id, "requester_id": None, "method": method,
        "inputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
        "outputs_hash": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
        "cost": {"tokens": "10", "usd_micros": "0", "wall_ms": "3", "rail_ref": None},
        "status": "OK", "reason": None,
        "parent_receipt_hash": parent_hash, "parent_performer_id": parent_perf,
        "log_policy": "best_effort", "ts": "2026-05-28T00:00:00Z",
        "nonce": "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",
    }


def build(performer_id, method, parent_hash, parent_perf):
    """Return (jws, receipt_id) for a fully-built signed receipt."""
    r = receipt(performer_id, method, parent_hash, parent_perf)
    payload = jcs(r).encode()
    jws, _ = sign(performer_id, payload)
    return jws, hashstr(payload)


def write(fname, name, receipts, valid, reason):
    (OUT / fname).write_text(json.dumps({
        "name": name, "command": "verify-chain",
        "input": {"receipts": receipts, "keys": REGISTRY, "policy": NO_POLICY},
        "anchor": {"valid": valid, "reason": reason, "chain_len": len(receipts)},
    }) + "\n")


# 1. valid 2-hop: leaf(srv-ec) -> root(srv-ed)
root_jws, root_id = build("srv-ed", "mcp:orchestrate", None, None)
leaf_jws, leaf_id = build("srv-ec", "mcp:tool", root_id, "srv-ed")
write("chain-valid-2hop.json", "chain/valid-2hop", [leaf_jws, root_jws], True, "ok")

# 2. valid 3-hop: leaf(srv-ed) -> mid(srv-ec) -> root(srv-ed)
r3_jws, r3_id = build("srv-ed", "mcp:orchestrate", None, None)
m3_jws, m3_id = build("srv-ec", "mcp:specialist", r3_id, "srv-ed")
l3_jws, l3_id = build("srv-ed", "mcp:tool", m3_id, "srv-ec")
write("chain-valid-3hop.json", "chain/valid-3hop", [l3_jws, m3_jws, r3_jws], True, "ok")

# 3. link mismatch: leaf points at a WRONG parent hash
wrong_parent_jws, _ = build("srv-ed", "mcp:orchestrate", None, None)
bad_leaf_jws, _ = build("srv-ec", "mcp:tool", hashstr(b"not-the-parent"), "srv-ed")
write("chain-link-mismatch.json", "chain/link-mismatch", [bad_leaf_jws, wrong_parent_jws], False, "link_mismatch")

# 4. forged parent: parent's signature byte flipped -> per-receipt verify fails
fp_root_jws, fp_root_id = build("srv-ed", "mcp:orchestrate", None, None)
h, p, s = fp_root_jws.split(".")
sb = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
sb[0] ^= 0xFF
forged_root = f"{h}.{p}.{b64u(bytes(sb))}"
fp_leaf_jws, _ = build("srv-ec", "mcp:tool", fp_root_id, "srv-ed")
write("chain-forged-parent.json", "chain/forged-parent-bad-sig", [fp_leaf_jws, forged_root], False, "receipt_invalid")

# 5. dangling parent: single leaf that claims a parent not provided (root hop has non-null parent)
dangling_jws, _ = build("srv-ec", "mcp:tool", hashstr(b"some-absent-parent"), "srv-ed")
write("chain-dangling-parent.json", "chain/dangling-parent", [dangling_jws], False, "malformed_chain")

# 6. foreign-parent splice: linkage hash is CORRECT, sigs valid, but parent identity != expected.
#    leaf expects parent_performer_id "srv-ed" but the provided (validly-signed) parent is "srv-ec".
fp2_parent_jws, fp2_parent_id = build("srv-ec", "mcp:orchestrate", None, None)  # real receipt, wrong performer
fp2_leaf_jws, _ = build("srv-ed", "mcp:tool", fp2_parent_id, "srv-ed")           # expects srv-ed parent
write("chain-parent-identity-mismatch.json", "chain/parent-identity-mismatch",
      [fp2_leaf_jws, fp2_parent_jws], False, "parent_identity_mismatch")

# 7. middle null parent: a non-root hop has parent_receipt_hash null -> malformed chain
mn_root_jws, _ = build("srv-ed", "mcp:orchestrate", None, None)
mn_leaf_jws, _ = build("srv-ec", "mcp:tool", None, None)  # leaf wrongly has null parent
write("chain-middle-null-parent.json", "chain/middle-null-parent", [mn_leaf_jws, mn_root_jws], False, "malformed_chain")

print("wrote chain vectors:")
for q in sorted(OUT.glob("chain-*.json")):
    print(" ", q.name)
