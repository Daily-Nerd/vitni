"""RFC 8032 section 7.1 known answers (data: rfc8032_section_7_1.json, copied
from the RFC text), plus bit flips that must all be refused."""
import json
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._paths import TESTS_DIR

DATA = json.loads((TESTS_DIR / "rfc8032_section_7_1.json").read_text(encoding="utf-8"))["tests"]


def flip(b, bit):
    out = bytearray(b)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


class Section71(unittest.TestCase):
    def test_the_five_vectors_are_the_five_in_the_rfc(self):
        self.assertEqual([t["name"] for t in DATA], ["1", "2", "3", "1024", "SHA(abc)"])
        self.assertEqual([len(t["message"]) // 2 for t in DATA], [0, 1, 2, 1023, 64])

    def test_all_verify(self):
        for t in DATA:
            self.assertTrue(
                V._ed25519_verify(bytes.fromhex(t["public"]), bytes.fromhex(t["signature"]), bytes.fromhex(t["message"])),
                t["name"],
            )

    def test_signature_bit_flips_are_refused(self):
        for t in DATA:
            pub, sig, msg = (bytes.fromhex(t[k]) for k in ("public", "signature", "message"))
            for bit in list(range(0, 512, 7)) + [0, 255, 256, 503, 511]:
                self.assertFalse(V._ed25519_verify(pub, flip(sig, bit), msg), (t["name"], bit))

    def test_message_bit_flips_are_refused(self):
        for t in DATA[1:]:
            pub, sig, msg = (bytes.fromhex(t[k]) for k in ("public", "signature", "message"))
            for bit in sorted({0, len(msg) * 8 - 1, len(msg) * 4}):
                self.assertFalse(V._ed25519_verify(pub, sig, flip(msg, bit)), (t["name"], bit))
        # and appending or removing a byte
        t = DATA[2]
        pub, sig, msg = (bytes.fromhex(t[k]) for k in ("public", "signature", "message"))
        self.assertFalse(V._ed25519_verify(pub, sig, msg + b"\x00"))
        self.assertFalse(V._ed25519_verify(pub, sig, msg[:-1]))

    def test_public_key_bit_flips_are_refused(self):
        t = DATA[1]
        pub, sig, msg = (bytes.fromhex(t[k]) for k in ("public", "signature", "message"))
        for bit in (0, 1, 100, 254):
            self.assertFalse(V._ed25519_verify(flip(pub, bit), sig, msg), bit)


if __name__ == "__main__":
    unittest.main()
