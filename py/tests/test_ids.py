"""Digests and content addresses: hashstring, digest, receipt-id."""
import hashlib
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._vectors import load_vectors, stdin_bytes

HANDLERS = {"digest": "_cmd_digest", "hashstring": "_cmd_hashstring", "receipt-id": "_cmd_receipt_id"}
DUP_REJECT = {"receipt-id"}


def run(command, stdin):
    """parse + handler, with the same rejection mapping the CLI applies."""
    try:
        doc = V.parse_json(stdin, dup="reject" if command in DUP_REJECT else "last", nonfinite="reject")
        return getattr(V, HANDLERS[command])(doc)
    except V._Reject:
        return {"error": "invalid_input"}


def vectors(prefix):
    return [v for v in load_vectors() if v["name"].startswith(prefix)]


class Hashstring(unittest.TestCase):
    def test_multihash_prefix_and_alphabet(self):
        sha = hashlib.sha256(b"hello").digest()
        want = "u" + V.b64url_encode(b"\x12\x20" + sha)
        self.assertEqual(V.hashstring(sha), want)
        self.assertEqual(want, "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA")
        self.assertTrue(V.hashstring(b"\xff" * 32).startswith("uEiD_"))  # url alphabet, no padding

    def test_command_matches_the_digest_vector(self):
        hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        want = {"hashstr": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA"}
        self.assertEqual(V._cmd_hashstring({"algo": "sha2-256", "digest_hex": hello}), want)
        self.assertEqual(V._cmd_hashstring({"algo": "sha2-256", "digest_hex": hello.upper()}), want)

    def test_rejections(self):
        hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        for member in (
            {"algo": "sha2-256", "digest_hex": "zz"},
            {"algo": "sha2-256", "digest_hex": "abc"},
            {"algo": "sha2-256", "digest_hex": " " + hello},
            {"algo": "sha2-256", "digest_hex": "0x" + hello},
            {"algo": "sha3", "digest_hex": hello},
            {"algo": "SHA2-256", "digest_hex": hello},
            {"algo": "", "digest_hex": hello},
        ):
            with self.assertRaises(V._Reject, msg=member):
                V._cmd_hashstring(member)

    def test_every_hashstring_vector_in_shape(self):
        vecs = vectors("hashstring/") + vectors("member/hashstring-unsupported-algo")
        self.assertGreaterEqual(len(vecs), 3)
        for vec in vecs:
            self.assertEqual(run("hashstring", stdin_bytes(vec)), vec["anchor"], vec["_file"])


class Digest(unittest.TestCase):
    def test_every_digest_vector_in_shape(self):
        vecs = vectors("digest/")
        self.assertGreaterEqual(len(vecs), 7)
        for vec in vecs:
            self.assertEqual(run("digest", stdin_bytes(vec)), vec["anchor"], vec["_file"])

    def test_two_inputs_two_outputs(self):
        self.assertNotEqual(V._cmd_digest({"bytes_b64": ""}), V._cmd_digest({"bytes_b64": "aGk="}))
        self.assertEqual(V._cmd_digest({"bytes_b64": "aGk"}), V._cmd_digest({"bytes_b64": "aGk="}))
        self.assertEqual(V._cmd_digest({"bytes_b64": "aGk="})["hashstr"], V.hashstring(hashlib.sha256(b"hi").digest()))


class ReceiptId(unittest.TestCase):
    def test_every_receipt_id_vector_in_shape(self):
        vecs = vectors("receipt-id/")
        self.assertGreaterEqual(len(vecs), 4)
        for vec in vecs:
            self.assertEqual(run("receipt-id", stdin_bytes(vec)), vec["anchor"], vec["_file"])

    def test_id_is_the_multihash_of_the_canonical_bytes(self):
        vec = [v for v in vectors("receipt-id/") if "receipt_id" in v["anchor"]][0]
        canonical = bytes.fromhex(vec["anchor"]["canonical_hex"])
        self.assertEqual(vec["anchor"]["receipt_id"], "u" + V.b64url_encode(b"\x12\x20" + hashlib.sha256(canonical).digest()))

    def test_receipt_id_member_is_refused(self):
        self.assertEqual(V._cmd_receipt_id({"receipt": {"receipt_id": "x", "v": "a"}}), {"error": "receipt_id_must_be_absent"})
        self.assertEqual(V._cmd_receipt_id({"receipt": {"receipt_id": None}}), {"error": "receipt_id_must_be_absent"})

    def test_a_second_receipt_gets_a_different_id_and_numbers_are_canonical(self):
        a = V._cmd_receipt_id({"receipt": {"v": "a", "z": [1.5e300, "é"], "n": None}})
        self.assertEqual(
            bytes.fromhex(a["canonical_hex"]), '{"n":null,"v":"a","z":[1.5e+300,"é"]}'.encode("utf-8"))
        b = V._cmd_receipt_id({"receipt": {"v": "b"}})
        self.assertNotEqual(a["receipt_id"], b["receipt_id"])
        self.assertEqual(a["receipt_id"], "uEiBhU7ss8a6oxzCh7a5B_TtlaWbtTdt33TDZDTEcpQLCVA")  # same bytes from Go


class Jcs(unittest.TestCase):
    def test_jcs_command_shape(self):
        out = V._cmd_jcs({"value": {"b": 1, "a": None}})
        self.assertEqual(out, {"byte_len": 16, "canonical_hex": b'{"a":null,"b":1}'.hex()})
        self.assertEqual(V._cmd_jcs({"value": None}), {"byte_len": 4, "canonical_hex": "6e756c6c"})


if __name__ == "__main__":
    unittest.main()
