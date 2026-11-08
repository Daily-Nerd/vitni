"""Second-oracle check: signatures made by the `cryptography` package must verify
in vitni_verify, tampered ones must not. NOT part of the stdlib-only gate: run
with   uv run --no-project --with cryptography==50.0.2 python -I -m unittest discover -s py/tests_cross -t py
Keys and messages come from a fixed-seed PRNG so a failure reproduces."""
import random
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import vitni_verify as V

N = V._P256_N


def tamper(rng, data):
    out = bytearray(data)
    out[rng.randrange(len(out))] ^= 1 << rng.randrange(8)
    return bytes(out)


class Ed25519Cross(unittest.TestCase):
    def test_200_sign_and_verify_with_tampering(self):
        rng = random.Random(25519)
        for i in range(200):
            key = ed25519.Ed25519PrivateKey.from_private_bytes(rng.randbytes(32))
            pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            msg = rng.randbytes(rng.randrange(0, 200))
            sig = key.sign(msg)
            self.assertTrue(V._ed25519_verify(pub, sig, msg), i)
            self.assertFalse(V._ed25519_verify(pub, tamper(rng, sig), msg), i)
            if msg:
                self.assertFalse(V._ed25519_verify(pub, sig, tamper(rng, msg)), i)
            self.assertFalse(V._ed25519_verify(tamper(rng, pub), sig, msg), i)


class P256Cross(unittest.TestCase):
    def test_200_sign_and_verify_with_tampering(self):
        rng = random.Random(256)
        for i in range(200):
            d = rng.randrange(1, N)
            key = ec.derive_private_key(d, ec.SECP256R1())
            nums = key.public_key().public_numbers()
            x, y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
            msg = rng.randbytes(rng.randrange(0, 200))
            r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            self.assertTrue(V._p256_verify(x, y, raw, msg), i)
            # the other half of a valid pair (high-S form) verifies too
            self.assertTrue(V._p256_verify(x, y, r.to_bytes(32, "big") + (N - s).to_bytes(32, "big"), msg), i)
            self.assertFalse(V._p256_verify(x, y, tamper(rng, raw), msg), i)
            if msg:
                self.assertFalse(V._p256_verify(x, y, raw, tamper(rng, msg)), i)
            self.assertFalse(V._p256_verify(tamper(rng, x), y, raw, msg), i)


if __name__ == "__main__":
    unittest.main()
