"""Every conformance vector through the dispatcher in process: the fast local
loop. conformance/compare.mjs stays the authority (it also runs the CLI)."""
import json
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._vectors import load_vectors, stdin_bytes


class EveryVector(unittest.TestCase):
    def test_in_scope_vectors_equal_their_anchor_and_the_rest_decline_exactly(self):
        declared, declined, unsupported = 0, 0, 0
        for vec in load_vectors():
            out = V.dispatch(vec["command"], lambda vec=vec: stdin_bytes(vec))
            if vec["command"] in V.DECLINED:
                self.assertEqual(out, V.jcs({"error": "unsupported_profile", "profile": "cmd:" + vec["command"]}), vec["_file"])
                declined += 1
            else:
                got = json.loads(out)
                anchor = vec.get("anchor")
                if anchor is None:
                    # no external anchor (the harness then needs two impls to agree): must be an answer
                    self.assertNotIn("error", got, vec["_file"])
                else:
                    self.assertEqual({k: got.get(k) for k in anchor}, anchor, vec["_file"])
                    self.assertTrue(set(got) == set(anchor) or "error" not in anchor, vec["_file"])
                if (anchor or {}).get("error") == "unsupported_command":
                    unsupported += 1
                else:
                    declared += 1
        self.assertGreater(declared, 150)
        self.assertGreater(declined, 50)
        self.assertEqual(unsupported, 3)

    def test_no_vector_needs_an_atom_python_does_not_declare(self):
        # a vector that is not declined must be answerable: its gating atoms are declared
        gating = {a for a in V.PROFILES}
        for vec in load_vectors():
            if vec["command"] in V.DECLINED:
                continue
            needed = {p for p in vec["profiles"] if p in {"alg:EdDSA", "alg:ES256", "canon:jcs", "canon:b64-strict"}}
            self.assertLessEqual(needed, gating, vec["_file"])


if __name__ == "__main__":
    unittest.main()
