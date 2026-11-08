"""ES256 is exactly 64-byte R||S over P-256. Complete addition (every edge goes
through the same add), range checks on r and s, key validity, no DER anywhere."""
import base64
import hashlib
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._vectors import load_vectors

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
G2 = (0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978,
      0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1)
G3 = (0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C,
      0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032)
NEG_G = (G[0], P - G[1])


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def be(x):
    return x.to_bytes(32, "big")


class Arithmetic(unittest.TestCase):
    def test_constants_agree_with_the_standard(self):
        self.assertEqual((V._P256_P, V._P256_N, V._P256_G), (P, N, G))
        self.assertEqual(G[1] ** 2 % P, (G[0] ** 3 - 3 * G[0] + V._P256_B) % P)

    def test_complete_addition_edges(self):
        add = V._p256_mul_add
        self.assertEqual(add(1, 0, G), G)
        self.assertEqual(add(2, 0, G), G2)
        self.assertEqual(add(3, 0, G), G3)
        self.assertEqual(add(1, 1, G), G2)             # Q = G: the add must double
        self.assertIsNone(add(1, 1, NEG_G))            # Q = -G: opposite points, infinity
        self.assertEqual(add(1, 1, G2), G3)            # Q = 2G
        self.assertEqual(add(2, 1, G), G3)             # distinct points, general formula
        self.assertEqual(add(0, 1, G3), G3)            # u1 = 0: first term is infinity
        self.assertIsNone(add(0, 0, G))                # both infinity
        self.assertIsNone(add(N, 0, G))                # n*G
        self.assertEqual(add(N + 1, 0, G), G)
        self.assertEqual(add(N - 1, 0, G), NEG_G)
        self.assertEqual(add(5, 7, G2), V._p256_mul_add(19, 0, G))  # 5G + 7(2G) = 19G
        self.assertEqual(add(0xDEADBEEF, 0xC0FFEE, G3), add((0xDEADBEEF + 3 * 0xC0FFEE) % N, 0, G))


def vector_es256():
    vec = [v for v in load_vectors() if v["name"] == "verify/valid-es256"][0]
    inp = vec["input"]
    header, payload, sig = inp["signed_receipt"].split(".")
    key = inp["keys"]["srv-ec"]["ec-1"]
    return b64u(key["x"]), b64u(key["y"]), b64u(sig), (header + "." + payload).encode("ascii")


def zero_lead_s_signature():
    """A valid ECDSA P-256 signature over a fixed message whose S has a zero
    leading byte. Test-only signer on the verifier's own curve code (the
    verifier is pinned by Wycheproof, so a signature it accepts is real): fixed
    key, deterministic nonces from a counter, first nonce that gives s < 2**248."""
    d = int.from_bytes(hashlib.sha256(b"vitni test key").digest(), "big") % (N - 1) + 1
    qx, qy = V._p256_mul_add(d, 0, G)
    msg = b"zero-lead-s"
    e = V._p256_digest_int(msg)
    for counter in range(100000):
        k = int.from_bytes(hashlib.sha256(b"vitni test nonce %d" % counter).digest(), "big") % (N - 1) + 1
        r = V._p256_mul_add(k, 0, G)[0] % N
        if r == 0:
            continue
        s = pow(k, -1, N) * (e + r * d) % N
        if 0 < s < 2 ** 248:
            return be(qx), be(qy), be(r) + be(s), msg
    raise AssertionError("no nonce gave a zero-leading S")


class Verify(unittest.TestCase):
    def test_valid_signature_from_the_conformance_vector(self):
        x, y, sig, msg = vector_es256()
        self.assertEqual(len(sig), 64)
        self.assertTrue(V._p256_verify(x, y, sig, msg))
        self.assertFalse(V._p256_verify(x, y, sig, msg + b"x"))
        self.assertFalse(V._p256_verify(x, y, sig, msg[:-1]))

    def test_high_s_is_accepted(self):
        x, y, sig, msg = vector_es256()
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        flipped = be(r) + be(N - s)
        self.assertTrue(V._p256_verify(x, y, flipped, msg))
        self.assertTrue(V._p256_verify(x, y, sig, msg))

    def test_r_and_s_range(self):
        x, y, sig, msg = vector_es256()
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        for bad_r, bad_s in ((0, s), (r, 0), (N, s), (r, N), (N + 1, s), (r, N + 1), (2 ** 256 - 1, s), (r, 2 ** 256 - 1)):
            self.assertFalse(V._p256_verify(x, y, be(bad_r) + be(bad_s), msg), (hex(bad_r), hex(bad_s)))

    def test_only_64_byte_raw_signatures(self):
        x, y, sig, msg = vector_es256()
        for bad in (sig[:63], sig + b"\x00", b"", sig[:32], sig + sig):
            self.assertFalse(V._p256_verify(x, y, bad, msg), len(bad))

    def test_a_wrong_length_signature_that_is_numerically_a_valid_one_is_refused(self):
        # Slicing r = sig[:32], s = sig[32:] reads a 63 or 65 byte string as the
        # same integers when S has a zero leading byte (drop it) or for any S
        # (prefix a zero). Only the length check refuses these, so they are the
        # cases that fail without it. A truncation that changes S is not enough
        # (the old test): it fails the arithmetic as well.
        x, y, sig, msg = zero_lead_s_signature()
        self.assertEqual(sig[32], 0)
        self.assertTrue(V._p256_verify(x, y, sig, msg))
        short = sig[:32] + sig[33:]
        long_ = sig[:32] + b"\x00" + sig[32:]
        self.assertEqual((len(short), len(long_)), (63, 65))
        self.assertEqual(int.from_bytes(short[32:], "big"), int.from_bytes(sig[32:], "big"))
        self.assertEqual(int.from_bytes(long_[32:], "big"), int.from_bytes(sig[32:], "big"))
        self.assertFalse(V._p256_verify(x, y, short, msg))
        self.assertFalse(V._p256_verify(x, y, long_, msg))

    def test_der_encoding_of_a_valid_signature_is_refused(self):
        x, y, sig, msg = vector_es256()

        def der_int(b):
            b = b.lstrip(b"\x00") or b"\x00"
            if b[0] & 0x80:
                b = b"\x00" + b
            return b"\x02" + bytes([len(b)]) + b

        body = der_int(sig[:32]) + der_int(sig[32:])
        der = b"\x30" + bytes([len(body)]) + body
        self.assertIn(len(der), (70, 71, 72))
        self.assertFalse(V._p256_verify(x, y, der, msg))

    def test_public_key_validity(self):
        x, y, sig, msg = vector_es256()
        xi, yi = int.from_bytes(x, "big"), int.from_bytes(y, "big")
        self.assertTrue(V._p256_verify(x, y, sig, msg))
        bad_keys = [
            (be(0), be(0)),                       # the (0, 0) pseudo-point
            (x, be(yi ^ 1)),                      # off the curve
            (be(xi ^ 1), y),
            (be(P), y),                           # coordinate == p
            (be(xi + P) if xi + P < 2 ** 256 else be(2 ** 256 - 1), y),  # coordinate >= p
            (x, be(P)),
            (x[:31], y),                          # wrong lengths
            (x, y + b"\x00"),
            (b"", b""),
        ]
        for kx, ky in bad_keys:
            self.assertFalse(V._p256_verify(kx, ky, sig, msg))

    def test_a_forgery_that_verifies_under_an_off_curve_key_is_refused(self):
        # Q = (5, 0) is a point of order 2 on y^2 = x^3 - 3x - 110, not on P-256.
        # The group formulas never use b, so without an explicit on-curve check
        # a signature can be built that "verifies": choose s, take r = x(u1*G)
        # and keep it when u2 = r/s is even (u2*Q is then infinity, R = u1*G).
        q = (5, 0)
        msg = b"forged"
        e = V._p256_digest_int(msg)
        for s in range(2, 200):
            w = pow(s, -1, N)
            r = V._p256_mul_add(e * w % N, 0, G)[0] % N
            if r * w % N % 2 == 0:
                break
        else:
            self.fail("no forgery parameters found")
        u1, u2 = e * w % N, r * w % N
        point = V._p256_mul_add(u1, u2, q)
        self.assertEqual(point[0] % N, r)  # the arithmetic alone WOULD accept
        self.assertFalse(V._p256_verify(be(q[0]), be(q[1]), be(r) + be(s), msg))

    def test_digest_is_reduced_mod_n_not_truncated(self):
        # e = int(sha256(msg)) % n: for a hash >= n the two differ; the vector
        # message hash just has to be valid either way, so pin the formula.
        x, y, sig, msg = vector_es256()
        self.assertEqual(V._p256_digest_int(msg), int.from_bytes(hashlib.sha256(msg).digest(), "big") % N)
        self.assertEqual(V._p256_digest_int(b"\xff" * 0), int.from_bytes(hashlib.sha256(b"").digest(), "big") % N)


if __name__ == "__main__":
    unittest.main()
