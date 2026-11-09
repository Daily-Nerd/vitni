#!/usr/bin/env python3
"""Generate `a2a-artifact-hash` conformance vectors (design §14 / CONTRACT §9).

Anchors computed by an independent Python oracle of the descriptor canonicalization.
Run: uv run --no-project python vectors/_gen_a2a.py
"""
import base64
import hashlib
import json
import pathlib

import _profiles

OUT = pathlib.Path(__file__).parent


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jcs(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def hashstr(content: bytes) -> str:
    return "u" + b64u(bytes([0x12, 0x20]) + hashlib.sha256(content).digest())


def descriptor_of(part: dict) -> dict:
    """Reference oracle for the §9 descriptor rule."""
    kind = part.get("kind")
    if kind == "text":
        return {"kind": "text", "text": part["text"]}
    if kind == "data":
        return {"kind": "data", "data": part["data"]}
    if kind == "file":
        f = part["file"]
        if "bytes" in f:
            raw = base64.b64decode(f["bytes"])
            return {"kind": "file", "digest": hashstr(raw),
                    "mimeType": f.get("mimeType"), "name": f.get("name")}
        if "uri" in f:
            return {"kind": "file", "uri": f["uri"], "declared_digest": f.get("declared_digest"),
                    "mimeType": f.get("mimeType"), "name": f.get("name")}
    raise ValueError("unsupported_part")


def write(fname, name, artifact, error=None):
    if error:
        anchor = {"error": error}
    else:
        descriptor = {"parts": [descriptor_of(p) for p in artifact["parts"]]}
        canon = jcs(descriptor).encode()
        anchor = {"outputs_hash": hashstr(canon), "descriptor_hex": canon.hex()}
    _profiles.write(OUT / fname, {
        "name": name, "command": "a2a-artifact-hash",
        "input": {"artifact": artifact}, "anchor": anchor,
    })


# 1. single text part
write("a2a-text.json", "a2a/text-part",
      {"parts": [{"kind": "text", "text": "hello world"}]})

# 2. single data part (nested object — JCS sorts keys)
write("a2a-data.json", "a2a/data-part",
      {"parts": [{"kind": "data", "data": {"b": 2, "a": [3, 1]}}]})

# 3. inline file (bytes hashed, not embedded)
write("a2a-file-inline.json", "a2a/file-inline",
      {"parts": [{"kind": "file", "file": {"bytes": base64.b64encode(b"PNGDATA").decode(),
                                           "mimeType": "image/png", "name": "x.png"}}]})

# 4. file by uri (never dereferenced)
write("a2a-file-uri.json", "a2a/file-uri",
      {"parts": [{"kind": "file", "file": {"uri": "https://store/x.bin",
                                           "declared_digest": hashstr(b"remote-bytes"),
                                           "mimeType": "application/octet-stream", "name": "x.bin"}}]})

# 5. mixed, multi-part, ORDER matters
write("a2a-mixed.json", "a2a/mixed-ordered",
      {"parts": [
          {"kind": "text", "text": "summary:"},
          {"kind": "data", "data": {"score": 0.9}},
          {"kind": "file", "file": {"bytes": base64.b64encode(b"\x00\x01\x02").decode(),
                                    "mimeType": "application/octet-stream", "name": None}},
      ]})

# 6. unsupported part (neither bytes nor uri)
write("a2a-unsupported.json", "a2a/unsupported-part",
      {"parts": [{"kind": "file", "file": {"mimeType": "x/y"}}]}, error="unsupported_part")

print("wrote a2a vectors:")
for q in sorted(OUT.glob("a2a-*.json")):
    print(" ", q.name)
