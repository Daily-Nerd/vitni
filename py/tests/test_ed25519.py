"""Ed25519 as Go and OpenSSL decide it: cofactorless, R compared by encoding,
S < L, A decoded with y reduced mod p, the ORIGINAL public-key bytes hashed."""
import base64
import hashlib
import json
import time
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._vectors import load_vectors

L = 2 ** 252 + 27742317777372353535851937790883648493
P = 2 ** 255 - 19
RFC1 = json.loads((_paths.TESTS_DIR / "rfc8032_section_7_1.json").read_text(encoding="utf-8"))["tests"][0]


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parts(seg):
    return bytes.fromhex(RFC1[seg])


class RangeAndLengths(unittest.TestCase):
    def test_s_at_or_above_l_is_refused(self):
        pub, sig, msg = parts("public"), parts("signature"), parts("message")
        s = int.from_bytes(sig[32:], "little")
        self.assertTrue(V._ed25519_verify(pub, sig, msg))
        for bad in (s + L, L, L + 1, 2 ** 256 - 1, 2 ** 255):
            forged = sig[:32] + bad.to_bytes(32, "little")
            self.assertFalse(V._ed25519_verify(pub, forged, msg), hex(bad))

    def test_lengths(self):
        pub, sig, msg = parts("public"), parts("signature"), parts("message")
        for p, s in ((pub[:31], sig), (pub + b"\x00", sig), (pub, sig[:63]), (pub, sig + b"\x00"), (b"", b""), (pub, b"")):
            self.assertFalse(V._ed25519_verify(p, s, msg))


class PinnedVerdicts(unittest.TestCase):
    """The ed-* verify vectors, judged at the primitive: same verdicts the
    pipeline is pinned to (identity key, sign bit, y = p + 1, order 8)."""

    def test_small_order_and_noncanonical_vectors(self):
        seen = 0
        for vec in load_vectors():
            if not vec["name"].startswith("verify/ed-"):
                continue
            inp = vec["input"]
            header, payload, sig = inp["signed_receipt"].split(".")
            key = next(iter(next(iter(inp["keys"].values())).values()))
            got = V._ed25519_verify(b64u(key["x"]), b64u(sig), (header + "." + payload).encode("ascii"))
            self.assertEqual(got, vec["anchor"]["valid"], vec["name"])
            seen += 1
        self.assertEqual(seen, 7)

    def test_the_two_order8_siblings_differ_only_in_the_public_key(self):
        a = [v for v in load_vectors() if v["name"] == "verify/ed-order8-a-r-eq-a"][0]
        b = [v for v in load_vectors() if v["name"] == "verify/ed-order8-b-r-eq-a"][0]
        ka = next(iter(next(iter(a["input"]["keys"].values())).values()))["x"]
        kb = next(iter(next(iter(b["input"]["keys"].values())).values()))["x"]
        self.assertNotEqual(ka, kb)
        self.assertEqual((a["anchor"]["valid"], b["anchor"]["valid"]), (False, True))


class OriginalPublicKeyBytes(unittest.TestCase):
    """A = the order-4 point with y = 0, written non-canonically as y = p. With
    R = identity and S = 0 the check is [k]A == identity, i.e. k % 4 == 0, and k
    is a hash of the key BYTES: hashing a re-encoded (canonical) key changes k."""

    IDENT = b"\x01" + b"\x00" * 31
    RAW = P.to_bytes(32, "little")      # y = p, sign 0 (non-canonical alias of y = 0)
    CANON = (0).to_bytes(32, "little")  # y = 0

    @staticmethod
    def k(r, a, m):
        return int.from_bytes(hashlib.sha512(r + a + m).digest(), "little") % L

    def find(self, raw_zero):
        for i in range(10000):
            m = b"msg-%d" % i
            kr, kc = self.k(self.IDENT, self.RAW, m) % 4, self.k(self.IDENT, self.CANON, m) % 4
            if (kr == 0) == raw_zero and (kc == 0) != raw_zero:
                return m
        raise AssertionError("no message found")

    def test_raw_bytes_are_hashed(self):
        sig = self.IDENT + b"\x00" * 32
        accept = self.find(raw_zero=True)    # raw hash gives k = 0 mod 4, canonical does not
        reject = self.find(raw_zero=False)   # the other way round
        self.assertTrue(V._ed25519_verify(self.RAW, sig, accept))
        self.assertFalse(V._ed25519_verify(self.RAW, sig, reject))
        # the same bytes with the canonical key behave the opposite way
        self.assertFalse(V._ed25519_verify(self.CANON, sig, accept))
        self.assertTrue(V._ed25519_verify(self.CANON, sig, reject))


class Time(unittest.TestCase):
    def test_fifty_verifies_each_under_250ms(self):
        pub, sig, msg = parts("public"), parts("signature"), parts("message")
        worst = 0.0
        for _ in range(50):
            t0 = time.perf_counter()
            self.assertTrue(V._ed25519_verify(pub, sig, msg))
            worst = max(worst, time.perf_counter() - t0)
        self.assertLess(worst, 0.25)


if __name__ == "__main__":
    unittest.main()
