"""The number layout is the part of JCS Python has no stdlib help for. Compare
it with V8's Number::toString on 20,000 fixed-seed doubles plus every power-of-2
and power-of-10 boundary and the subnormals, in ONE node process.

Node missing is a failure, never a skip: there is no disable flag. CI sets
VITNI_REQUIRE_NODE=1 for explicitness only; it changes nothing here."""
import random
import shutil
import struct
import subprocess
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V

NODE_SCRIPT = r"""
const lines = require('fs').readFileSync(0, 'utf8').split('\n').filter((l) => l.length);
const out = lines.map((h) => { const b = Buffer.from(h, 'hex'); return String(b.readDoubleBE(0)); });
process.stdout.write(out.join('\n') + '\n');
"""


def bits_to_double(bits):
    return struct.unpack(">d", struct.pack(">Q", bits))[0]


def double_to_bits(x):
    return struct.unpack(">Q", struct.pack(">d", x))[0]


def samples():
    rng = random.Random(8785)
    bits = [rng.getrandbits(64) for _ in range(20000)]
    out = [bits_to_double(b) for b in bits]
    for k in range(-1074, 1024):
        x = 2.0 ** k
        out += [x, -x]
        b = double_to_bits(x)
        out += [bits_to_double(b + 1), bits_to_double(b - 1)]
    for k in range(-323, 309):
        x = float("1e%d" % k)
        out += [x, -x]
        b = double_to_bits(x)
        out += [bits_to_double(b + 1), bits_to_double(b - 1)]
    out += [5e-324, 2.2250738585072014e-308, 1.7976931348623157e308, 0.0, -0.0, 4.35, 0.1 + 0.2]
    for k in range(0, 52):  # subnormals with few significant bits
        out.append(bits_to_double(1 << k))
    return [x for x in out if x - x == 0.0]  # finite only


class NumberDifferential(unittest.TestCase):
    def test_es_number_equals_v8_to_string(self):
        node = shutil.which("node")
        if node is None:
            self.fail("node is required for the number differential (no skip, no disable flag)")
        xs = samples()
        self.assertGreater(len(xs), 20000)
        stdin = "".join("%016x\n" % double_to_bits(x) for x in xs)
        res = subprocess.run([node, "-e", NODE_SCRIPT], input=stdin.encode("ascii"), capture_output=True, timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr.decode("utf-8", "replace"))
        theirs = res.stdout.decode("utf-8").split("\n")[:-1]
        self.assertEqual(len(theirs), len(xs))
        bad = [(repr(x), V._es_number(x), t) for x, t in zip(xs, theirs) if V._es_number(x) != t]
        self.assertEqual(bad[:5], [], "first mismatches (value, ours, node)")


if __name__ == "__main__":
    unittest.main()
