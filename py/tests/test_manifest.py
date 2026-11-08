"""The vendored Wycheproof data is exactly the pinned upstream bytes."""
import hashlib
import json
import unittest

from ._paths import ROOT, VECTORS, WYCHEPROOF

P1363 = "ecdsa_secp256r1_sha256_p1363_test.json"
ED25519 = "ed25519_test.json"
COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"

# The hard cases the P-256 file must keep (counts are the upstream numbers).
P1363_FLAGS = {
    "ArithmeticError": 110,
    "SpecialCaseHash": 54,
    "EdgeCasePublicKey": 24,
    "SmallRandS": 16,
    "ModularInverse": 15,
    "SignatureSize": 12,
    "PointDuplication": 7,
    "RangeCheck": 4,
    "IntegerOverflow": 4,
    "EdgeCaseShamirMultiplication": 1,
}


def manifest():
    return json.loads((WYCHEPROOF / "MANIFEST.json").read_text(encoding="utf-8"))


def tests_of(name):
    doc = json.loads((WYCHEPROOF / name).read_text(encoding="utf-8"))
    return [t for g in doc["testGroups"] for t in g["tests"]]


class Manifest(unittest.TestCase):
    def test_pins_upstream_commit(self):
        m = manifest()
        self.assertEqual(m["upstream"], "https://github.com/C2SP/wycheproof")
        self.assertEqual(m["commit"], COMMIT)
        self.assertEqual(set(m["files"]), {P1363, ED25519})

    def test_hashes_and_sizes(self):
        for name, meta in manifest()["files"].items():
            data = (WYCHEPROOF / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), meta["sha256"], name)
            self.assertEqual(len(data), meta["size"], name)
        files = manifest()["files"]
        self.assertEqual(files[P1363]["sha256"], "c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986")
        self.assertEqual(files[P1363]["size"], 242550)
        self.assertEqual(files[ED25519]["sha256"], "ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3")
        self.assertEqual(files[ED25519]["size"], 172628)

    def test_license_is_apache(self):
        text = (WYCHEPROOF / "LICENSE").read_text(encoding="utf-8")
        self.assertTrue(text.strip())
        self.assertIn("Apache License", text)

    def test_counts(self):
        files = manifest()["files"]
        for name, total, results in (
            (P1363, 262, {"valid": 173, "invalid": 89}),
            (ED25519, 210, {"valid": 117, "invalid": 64, "acceptable": 29}),
        ):
            tests = tests_of(name)
            self.assertEqual(len(tests), total, name)
            got = {}
            flags = {}
            for t in tests:
                got[t["result"]] = got.get(t["result"], 0) + 1
                for f in t["flags"]:
                    flags[f] = flags.get(f, 0) + 1
            self.assertEqual(got, results, name)
            self.assertEqual(files[name]["tests"], total)
            self.assertEqual(files[name]["results"], results)
            self.assertEqual(files[name]["flags"], flags)

    def test_p1363_keeps_the_hard_flags(self):
        flags = manifest()["files"][P1363]["flags"]
        for flag, count in P1363_FLAGS.items():
            self.assertEqual(flags.get(flag), count, flag)
        self.assertIn("PointDuplication", flags)
        self.assertIn("EdgeCaseShamirMultiplication", flags)

    def test_der_file_is_not_vendored(self):
        self.assertFalse((WYCHEPROOF / "ecdsa_secp256r1_sha256_test.json").exists())

    def test_not_in_vectors_dir(self):
        # compare.mjs ingests everything under conformance/vectors/.
        for p in VECTORS.iterdir():
            self.assertNotIn("wycheproof", p.name.lower())
        self.assertNotEqual(WYCHEPROOF.parent.resolve(), VECTORS.resolve())


class AcceptableExpected(unittest.TestCase):
    def test_one_pinned_outcome_per_acceptable_tcid(self):
        pinned = json.loads((ROOT / "py" / "tests" / "acceptable_expected.json").read_text(encoding="utf-8"))
        acceptable = {str(t["tcId"]) for t in tests_of(ED25519) if t["result"] == "acceptable"}
        self.assertEqual(len(pinned), 29)
        self.assertEqual(set(pinned), acceptable)
        self.assertTrue(all(v is True for v in pinned.values()))


if __name__ == "__main__":
    unittest.main()
