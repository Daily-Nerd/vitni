"""The vendored Wycheproof files, the external oracle for the curve math. Counts
are checked against the manifest so a truncated file cannot pass."""
import json
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._paths import TESTS_DIR, WYCHEPROOF


def groups(name):
    return json.loads((WYCHEPROOF / name).read_text(encoding="utf-8"))["testGroups"]


def manifest(name):
    return json.loads((WYCHEPROOF / "MANIFEST.json").read_text(encoding="utf-8"))["files"][name]


class Ed25519(unittest.TestCase):
    NAME = "ed25519_test.json"

    def test_ed25519_all(self):
        pinned = json.loads((TESTS_DIR / "acceptable_expected.json").read_text(encoding="utf-8"))
        counts = {}
        for g in groups(self.NAME):
            pub = bytes.fromhex(g["publicKey"]["pk"])
            for t in g["tests"]:
                counts[t["result"]] = counts.get(t["result"], 0) + 1
                got = V._ed25519_verify(pub, bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"]))
                if t["result"] == "valid":
                    want = True
                elif t["result"] == "invalid":
                    want = False
                else:  # acceptable: ONE pinned outcome per tcId, same for every verifier
                    want = pinned[str(t["tcId"])]
                self.assertEqual(got, want, (t["tcId"], t["comment"], t["flags"]))
        self.assertEqual(counts, manifest(self.NAME)["results"])
        self.assertEqual(counts, {"valid": 117, "invalid": 64, "acceptable": 29})


if __name__ == "__main__":
    unittest.main()
