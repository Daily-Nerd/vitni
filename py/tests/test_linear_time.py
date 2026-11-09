"""Strict decoding of untrusted input runs in linear time in its length."""
import time
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._jws import b64u, jws, registry

BOUND = 2.0  # seconds; the linear scan takes milliseconds, the quadratic one minutes
# An opening quote that never closes, then escaped quotes: each one used to
# restart a scan to the end of the text.
UNCLOSED = b'{"a":"' + b'\\"' * 100_000


class LinearTimeTest(unittest.TestCase):
    def timed(self, fn):
        t0 = time.perf_counter()
        out = fn()
        self.assertLess(time.perf_counter() - t0, BOUND)
        return out

    def test_parse_json_rejects_unclosed_string_fast(self):
        def run():
            with self.assertRaises(V._Reject):
                V.parse_json(UNCLOSED, dup="last", nonfinite="defer")
        self.timed(run)

    def test_unclosed_string_after_brackets_fast(self):
        def run():
            with self.assertRaises(V._Reject):
                V.parse_json(b"[[[" + UNCLOSED, dup="reject", nonfinite="reject")
        self.timed(run)

    def test_verify_payload_segment_malformed_fast(self):
        token = jws(payload_bytes=UNCLOSED, sign=False)
        r = self.timed(lambda: V.verify(token, registry()))
        self.assertEqual(r, {"reason": "malformed", "valid": False})

    def test_verify_header_segment_malformed_fast(self):
        token = jws(header=UNCLOSED, sign=False)
        r = self.timed(lambda: V.verify(token, registry()))
        self.assertEqual(r, {"reason": "malformed", "valid": False})

    def test_depth_tokenizing_unchanged_for_valid_text(self):
        self.assertTrue(V._within_depth('{"a":"[[[\\"]]]","b":[1,{"c":[]}]}'))
        self.assertTrue(V._within_depth("[" * V.MAX_DEPTH + "]" * V.MAX_DEPTH))
        self.assertFalse(V._within_depth("[" * (V.MAX_DEPTH + 1)))
        self.assertFalse(V._within_depth('"x\\\\"' + "[" * (V.MAX_DEPTH + 1)))
        self.assertTrue(V._within_depth('"' + "[" * 500 + '"'))


if __name__ == "__main__":
    unittest.main()
