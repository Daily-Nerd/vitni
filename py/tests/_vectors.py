"""Reads conformance/vectors/*.json the way conformance/harness.mjs does, so the
in-process tests never keep a copy of the vector list or of its stdin rules."""
import base64
import json

from ._paths import VECTORS

INPUT_FORMS = ("input", "input_raw", "input_raw_b64")


def load_vectors():
    out = []
    for path in sorted(VECTORS.glob("*.json")):
        vec = json.loads(path.read_text(encoding="utf-8"))
        vec["_file"] = path.name
        out.append(vec)
    return out


def stdin_bytes(vec):
    """The exact stdin byte string of one vector (exactly one input form)."""
    forms = [k for k in INPUT_FORMS if k in vec]
    if len(forms) != 1:
        raise ValueError(f"{vec['_file']}: exactly one input form required, found {forms}")
    if "input_raw_b64" in vec:
        return base64.b64decode(vec["input_raw_b64"], validate=True)
    if "input_raw" in vec:
        return vec["input_raw"].encode("utf-8")
    return json.dumps(vec["input"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
