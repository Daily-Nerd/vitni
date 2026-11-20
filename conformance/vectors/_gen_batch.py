#!/usr/bin/env python3
"""Generate `verify-batch` conformance vectors.

No cryptography here: every question is the input of an existing `verify`
vector, read back from vectors/ and paired with that vector's own anchor, so the
batch vectors cannot disagree with the verify vectors they reuse. Run it AFTER
_gen_verify.py (the verify vectors must exist).

Run: uv run --no-project python _gen_batch.py   (from conformance/vectors)

Vectors written:
  batch-empty                         {"questions":[]}
  batch-mixed-verdicts                ok, bad_signature, unknown_key, revoked_key, context_mismatch
  batch-mixed-algs                    one EdDSA and one ES256 question, each with its own keys
  batch-invalid-element-among-valid   a non-object or ill-typed element answers alone
  batch-empty-keys                    a verifying receipt with keys {} is unknown_key
  batch-null-members                  absent and null members are the verdict malformed
  batch-duplicate-keys-last-wins      the whole text is last-wins, as for verify
  batch-depth-128                     the deepest text the batch accepts
  batch-max-questions                 exactly the maximum (unanchored, see below)
  neg-batch-questions-*               missing, null, object, string: top-level invalid_input
  neg-batch-too-large                 the maximum plus one: batch_too_large
  neg-batch-lone-surrogate            a text fault fails the whole batch
  neg-batch-nonfinite
  neg-batch-depth-129

batch-max-questions carries no anchor: its 65536 results would make the vector
about 2.4 MB. It still pins the boundary from the answering side, because an
error output on an unanchored vector fails the harness (NOANCHOR), and
neg-batch-too-large pins it from the other side.
"""
import json
import pathlib

import _profiles

OUT = pathlib.Path(__file__).parent
MAX_QUESTIONS = 65536


def load(name: str) -> dict:
    return json.loads((OUT / name).read_text())


def question(name: str, reason: str) -> tuple[dict, dict]:
    """(a verify vector's input, the result it must produce), checked against the reason expected."""
    vec = load(name)
    assert vec["command"] == "verify" and "input" in vec, name
    assert vec["anchor"]["reason"] == reason, (name, vec["anchor"])
    return vec["input"], canon(vec["anchor"])


def canon(obj):
    """Sorted keys, the order JCS prints them in."""
    return json.loads(json.dumps(obj, sort_keys=True))


def verdict(reason: str) -> dict:
    return {"reason": reason, "valid": reason == "ok"}


INVALID = {"error": "invalid_input"}


def raw(*elements: str) -> str:
    return '{"questions":[' + ",".join(elements) + "]}"


def dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def write_input(fname, name, questions, results):
    _profiles.write(OUT / fname, {
        "name": name, "command": "verify-batch",
        "input": {"questions": questions},
        "anchor": {"results": results},
    })


def write_raw(fname, name, text, anchor=None):
    vec = {"name": name, "command": "verify-batch", "input_raw": text}
    if anchor is not None:
        vec["anchor"] = anchor
    _profiles.write(OUT / fname, vec)


ok_q, ok_r = question("verify-valid-es256.json", "ok")
ed_q, ed_r = question("verify-local-valid.json", "ok")
bad_q, bad_r = question("verify-bad-signature.json", "bad_signature")
unk_q, unk_r = question("verify-empty-kid-unregistered.json", "unknown_key")
rev_q, rev_r = question("verify-key-revoked-and-mismatched.json", "revoked_key")
ctx_q, ctx_r = question("verify-context-mismatch.json", "context_mismatch")

# 1. empty list
write_input("batch-empty.json", "batch/empty", [], [])

# 2. one verdict of each of the five kinds, in an order that is not the sorted one
write_input("batch-mixed-verdicts.json", "batch/mixed-verdicts",
            [ctx_q, ok_q, rev_q, bad_q, unk_q], [ctx_r, ok_r, rev_r, bad_r, unk_r])

# 3. two algorithms in one batch, each question with its own registry
write_input("batch-mixed-algs.json", "batch/mixed-algs", [ed_q, ok_q, ed_q], [ed_r, ok_r, ed_r])

# 4. an element that is not a valid question answers alone and moves no other result
bad_type_q = {**ok_q, "signed_receipt": 5}
bad_keys_q = {**ok_q, "keys": []}
bad_policy_q = {**ok_q, "policy": {"expected_binding": 5}}
write_input("batch-invalid-element-among-valid.json", "batch/invalid-element-among-valid",
            [ok_q, 5, bad_type_q, None, bad_q, [], bad_keys_q, "x", bad_policy_q, ok_q],
            [ok_r, INVALID, INVALID, INVALID, bad_r, INVALID, INVALID, INVALID, INVALID, ok_r])

# 5. a receipt that verifies under its own keys is unknown_key under keys {}
write_input("batch-empty-keys.json", "batch/empty-keys",
            [{**ok_q, "keys": {}}, ok_q, {**ok_q, "keys": {}, "policy": {}}],
            [verdict("unknown_key"), ok_r, verdict("unknown_key")])

# 6. absent and null members are verdicts (malformed), not input errors
write_input("batch-null-members.json", "batch/null-members",
            [{}, {"signed_receipt": None, "keys": None, "policy": None}, {"keys": {}}],
            [verdict("malformed")] * 3)

# 7. duplicate keys are last-wins over the whole text, at both levels: the first
#    `questions` is dropped, and inside the element the later null signed_receipt wins
dup_element = ('{"signed_receipt":' + dumps(ok_q["signed_receipt"]) + ',"keys":' + dumps(ok_q["keys"])
               + ',"signed_receipt":null}')
write_raw("batch-duplicate-keys-last-wins.json", "batch/duplicate-keys-last-wins",
          '{"questions":[],"questions":[' + dup_element + "," + dumps(ok_q) + "]}",
          {"results": [verdict("malformed"), ok_r]})

# 8. nesting: the top-level object is depth 1, `questions` 2, an element 3, so an
#    element member holding n nested arrays is at depth 3 + n. 125 is the last
#    accepted depth (128), where a lone verify accepts 127.
write_raw("batch-depth-128.json", "batch/depth-128",
          raw('{"x":' + "[" * 125 + "]" * 125 + "}", dumps(ok_q)),
          {"results": [verdict("malformed"), ok_r]})

# 9. the maximum (unanchored: see the module docstring) and one more
write_raw("batch-max-questions.json", "batch/max-questions", raw(*["{}"] * MAX_QUESTIONS))
write_raw("neg-batch-too-large.json", "batch/too-large", raw(*["{}"] * (MAX_QUESTIONS + 1)),
          {"error": "batch_too_large"})

# 10. the batch itself must be {"questions": [...]}
for fname, name, text in (
    ("neg-batch-questions-absent.json", "batch/questions-absent", "{}"),
    ("neg-batch-questions-null.json", "batch/questions-null", '{"questions":null}'),
    ("neg-batch-questions-object.json", "batch/questions-object", '{"questions":{}}'),
    ("neg-batch-questions-string.json", "batch/questions-string", '{"questions":"x"}'),
    ("neg-batch-questions-case.json", "batch/questions-member-case", '{"Questions":[]}'),
):
    write_raw(fname, name, text, {"error": "invalid_input"})

# 11. a fault found on the raw text fails the whole batch, however good the other
#     elements are. A lone verify answers the same text fault with invalid_input too,
#     but depth differs: an element sits two levels deeper than a lone verify input.
write_raw("neg-batch-lone-surrogate.json", "batch/lone-surrogate",
          raw(dumps(ok_q), '{"x":"\\ud800"}'), {"error": "invalid_input"})
write_raw("neg-batch-nonfinite.json", "batch/nonfinite",
          raw(dumps(ok_q), '{"x":1e400}'), {"error": "invalid_input"})
write_raw("neg-batch-depth-129.json", "batch/depth-129",
          raw(dumps(ok_q), '{"x":' + "[" * 126 + "]" * 126 + "}"), {"error": "invalid_input"})
