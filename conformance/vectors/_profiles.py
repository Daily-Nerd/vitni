"""The only tagger: computes a vector's `profiles` member from its own data.

A profile atom exists only if conformance/profiles.json lists it. This module
never invents one: a value that would need a new atom (for example a payload
binding that is not catalogued) raises instead of being skipped. `cmd:<command>`
atoms are derived by the harness from the `command` member and are never stored.

Rules (design 4.2):
  alg:X            the alg of the registry key that SIGNS each JWS in the vector
                   (resolve payload.performer_id + header.kid in `keys`); keygen
                   and sign produce Ed25519, so they add alg:EdDSA. A JWS that
                   does not decode or resolve adds nothing, and so does a registry
                   alg outside the catalog (that case is the verdict
                   alg_not_allowed, the same on every verifier).
  canon:jcs        command in JCS_COMMANDS, or sse-outputs-hash in mode sse-jsonrpc
  canon:b64-strict the input carries a standard-base64 member, or the command is
                   verify / verify-chain (segments and key material)
  binding:X        payload.binding of each decodable JWS, receipt.binding for
                   receipt-id
"""
import base64
import json
import pathlib

HERE = pathlib.Path(__file__).parent
CATALOG = json.loads((HERE.parent / "profiles.json").read_text())
ATOMS = {a["id"] for a in CATALOG["atoms"]}
ALG_ATOMS = {a[len("alg:"):] for a in ATOMS if a.startswith("alg:")}

INPUT_FORMS = ("input", "input_raw", "input_raw_b64")
JCS_COMMANDS = {"jcs", "receipt-id", "cost-canon", "a2a-artifact-hash", "verify", "verify-chain", "sign"}
B64_MEMBERS = ("bytes_b64", "raw_b64", "seed_b64", "private_key_b64")
B64_COMMANDS = {"verify", "verify-chain"}


def _stdin_object(vec: dict) -> dict:
    """The stdin of a vector as an object; {} when it is not a JSON object (the
    stdin-gate vectors carry text that is deliberately not one)."""
    if "input" in vec:
        obj = vec["input"]
    else:
        try:
            if "input_raw_b64" in vec:
                text = base64.b64decode(vec["input_raw_b64"]).decode("utf-8")
            else:
                text = vec.get("input_raw", "")
            obj = json.loads(text)
        except (ValueError, TypeError):
            return {}
    return obj if isinstance(obj, dict) else {}


def _jws_parts(jws):
    """(header, payload) of a compact JWS, or None when it does not decode."""
    if not isinstance(jws, str):
        return None
    segs = jws.split(".")
    if len(segs) != 3:
        return None
    out = []
    for seg in segs[:2]:
        try:
            raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
            val = json.loads(raw.decode("utf-8"))
        except (ValueError, TypeError):
            return None
        if not isinstance(val, dict):
            return None
        out.append(val)
    return out[0], out[1]


def _signing_alg(parts, keys):
    header, payload = parts
    if not isinstance(keys, dict):
        return None
    entry = keys.get(payload.get("performer_id") if isinstance(payload.get("performer_id"), str) else None)
    kid = header.get("kid")
    if not isinstance(entry, dict) or not isinstance(kid, str):
        return None
    key = entry.get(kid)
    if not isinstance(key, dict):
        return None
    alg = key.get("alg")
    return alg if isinstance(alg, str) and alg in ALG_ATOMS else None


def _jws_inputs(vec: dict, obj: dict):
    cmd = vec.get("command")
    if cmd == "verify":
        return [obj.get("signed_receipt")]
    if cmd == "verify-chain":
        r = obj.get("receipts")
        return list(r) if isinstance(r, list) else []
    if cmd == "sign":
        a = vec.get("anchor")
        return [a.get("signed_receipt")] if isinstance(a, dict) else []
    return []


def _has_b64_member(vec: dict, obj: dict) -> bool:
    if any(m in obj for m in B64_MEMBERS):
        return True
    art = obj.get("artifact")
    parts = art.get("parts") if isinstance(art, dict) else None
    if isinstance(parts, list):
        for p in parts:
            f = p.get("file") if isinstance(p, dict) else None
            if isinstance(f, dict) and "bytes" in f:
                return True
    return False


def atoms_for(vec: dict) -> list:
    cmd = vec.get("command")
    obj = _stdin_object(vec)
    atoms = set()

    if cmd in JCS_COMMANDS or (cmd == "sse-outputs-hash" and obj.get("mode") == "sse-jsonrpc"):
        atoms.add("canon:jcs")
    if cmd in B64_COMMANDS or _has_b64_member(vec, obj):
        atoms.add("canon:b64-strict")
    if cmd in ("keygen", "sign"):
        atoms.add("alg:EdDSA")

    keys = obj.get("keys")
    for jws in _jws_inputs(vec, obj):
        parts = _jws_parts(jws)
        if parts is None:
            continue
        alg = _signing_alg(parts, keys)
        if alg is not None:
            atoms.add(f"alg:{alg}")
        binding = parts[1].get("binding")
        if isinstance(binding, str):
            atoms.add(f"binding:{binding}")
    if cmd == "receipt-id":
        r = obj.get("receipt")
        binding = r.get("binding") if isinstance(r, dict) else None
        if isinstance(binding, str):
            atoms.add(f"binding:{binding}")

    unknown = sorted(atoms - ATOMS)
    if unknown:
        raise ValueError(
            f"{vec.get('name')}: atom(s) {unknown} are not in conformance/profiles.json; "
            "add them to the catalog in the same commit, the tagger never invents one")
    return sorted(atoms)


def finalize(vec: dict) -> dict:
    """The vector with `profiles` inserted right after `command` (stable order)."""
    forms = [k for k in INPUT_FORMS if k in vec]
    if len(forms) != 1:
        raise ValueError(f"{vec.get('name')}: exactly one of {INPUT_FORMS} required, found {forms}")
    if "profiles" in vec:
        raise ValueError(f"{vec.get('name')}: `profiles` is computed by _profiles.py, a generator must not set it")
    out = {}
    for k, v in vec.items():
        out[k] = v
        if k == "command":
            out["profiles"] = atoms_for(vec)
    if "command" not in vec:
        raise ValueError(f"{vec.get('name')}: no `command` member")
    return out


def write(path: pathlib.Path, vec: dict) -> None:
    pathlib.Path(path).write_text(json.dumps(finalize(vec)) + "\n")
