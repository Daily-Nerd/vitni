"""One strict decoder per input format, each rejecting what the stdlib default
would accept (the lenient defaults are the bug class this file guards)."""
import json
import unittest

from . import _paths  # noqa: F401  (puts py/ on sys.path)
import vitni_verify as V


class B64Url(unittest.TestCase):
    def test_accepts_only_canonical_unpadded(self):
        self.assertEqual(V.b64url_decode_strict("aGVsbG8"), b"hello")
        self.assertEqual(V.b64url_decode_strict(""), b"")
        self.assertEqual(V.b64url_decode_strict("-_8"), b"\xfb\xff")
        self.assertEqual(V.b64url_decode_strict("AAAA"), b"\x00\x00\x00")

    def test_rejects_everything_else(self):
        for s in (
            "aGVsbG8=",    # padding
            "a+/",         # standard alphabet
            "+/8",
            "a b",         # whitespace
            "aGVsbG8\n",   # trailing newline (a `$` regex would let it through)
            "aGVs\nbG8",   # newline mid-string
            "aGVsbG9",     # non-zero trailing bits
            "aGVsb",       # length 1 mod 4
            "a",
            "éé",  # non-ASCII
        ):
            with self.assertRaises(V._Reject, msg=repr(s)):
                V.b64url_decode_strict(s)

    def test_rejects_non_strings(self):
        for v in (b"aGVsbG8", None, 5):
            with self.assertRaises(V._Reject):
                V.b64url_decode_strict(v)


class B64Std(unittest.TestCase):
    def test_accepts_canonical_padded_and_unpadded(self):
        self.assertEqual(V.b64std_decode_strict("aGVsbG8="), b"hello")
        self.assertEqual(V.b64std_decode_strict("aGVsbG8"), b"hello")
        self.assertEqual(V.b64std_decode_strict(""), b"")
        self.assertEqual(V.b64std_decode_strict("+/8="), b"\xfb\xff")
        self.assertEqual(V.b64std_decode_strict("aGk="), b"hi")

    def test_rejects_everything_else(self):
        for s in (
            "aGVsbG8==",   # excess padding
            "aGVs\nbG8=",  # embedded newline (validate=False would drop it)
            "aGVsbG9=",    # non-canonical trailing bits
            "-_8=",        # url alphabet
            "aGVsbG8 =",
            "a",
            "aGVsb",       # length 1 mod 4
            "====",
            "aGk=\n",
        ):
            with self.assertRaises(V._Reject, msg=repr(s)):
                V.b64std_decode_strict(s)


class Hex(unittest.TestCase):
    def test_accepts_even_length_hex_of_either_case(self):
        self.assertEqual(V.hex_decode_strict("00ff"), b"\x00\xff")
        self.assertEqual(V.hex_decode_strict("00FF"), b"\x00\xff")
        self.assertEqual(V.hex_decode_strict(""), b"")

    def test_rejects_what_fromhex_would_skip_or_accept(self):
        for s in (" 00", "00 ff", "00\n", "0", "0x00", "zz", "000"):
            with self.assertRaises(V._Reject, msg=repr(s)):
                V.hex_decode_strict(s)


class Utf8(unittest.TestCase):
    def test_accepts_valid_text(self):
        self.assertEqual(V.utf8_decode_strict(b"abc"), "abc")
        self.assertEqual(V.utf8_decode_strict("é".encode()), "é")
        self.assertEqual(V.utf8_decode_strict(b"\xf0\x9f\x98\x80"), "\U0001F600")

    def test_rejects(self):
        for b in (
            b"\xef\xbb\xbfabc",   # BOM
            b"\xff",
            b"\xc0\x80",          # overlong NUL
            b"\xed\xa0\x80",      # encoded surrogate
            b"\xf4\x90\x80\x80",  # above U+10FFFF
        ):
            with self.assertRaises(V._Reject, msg=repr(b)):
                V.utf8_decode_strict(b)


def parse(text, dup="last", nonfinite="reject"):
    data = text if isinstance(text, bytes) else text.encode("utf-8")
    return V.parse_json(data, dup=dup, nonfinite=nonfinite)


class ParseJson(unittest.TestCase):
    def test_parses_and_keeps_numbers_as_floats(self):
        v = parse(' \t\r\n{"a":[1,2.5,true,null,"x"],"b":{}}\n')
        self.assertEqual(v, {"a": [1, 2.5, True, None, "x"], "b": {}})
        self.assertIs(type(v["a"][0]), float)
        self.assertIs(v["a"][2], True)

    def test_text_shape_errors(self):
        for text in (b"", b"{}x", b"{} \x00", b"{", b'{"a":01}', b"[1.]", b"[.5]", b"[+1]", b"[-]",
                     b'["a\nb"]', b'["\\x"]', b"{'a':1}", b"[1,]"):
            with self.assertRaises(V._Reject, msg=repr(text)):
                parse(text)

    def test_bytes_are_never_autodetected_as_utf16(self):
        # json.loads(bytes) sniffs UTF-16/32; the parser must see decoded text only.
        for enc in ("utf-16", "utf-16-le", "utf-16-be", "utf-32"):
            with self.assertRaises(V._Reject, msg=enc):
                parse('{"a":1}'.encode(enc))
        # and the baseline trap really exists in the stdlib
        self.assertEqual(json.loads('{"a":1}'.encode("utf-16")), {"a": 1})

    def test_bom_and_invalid_utf8(self):
        for b in (b'\xef\xbb\xbf{}', b'{"a":"\xff"}', b'{"a":"\xed\xa0\x80"}'):
            with self.assertRaises(V._Reject):
                parse(b)

    def test_constants_are_always_rejected(self):
        for text in ("[NaN]", "[Infinity]", "[-Infinity]"):
            for policy in ("reject", "defer"):
                with self.assertRaises(V._Reject, msg=(text, policy)):
                    parse(text, nonfinite=policy)

    def test_overflow_follows_the_policy(self):
        for text in ("[1e400]", "[-1e400]", "[" + "9" * 5000 + "]"):
            with self.assertRaises(V._Reject, msg=text[:12]):
                parse(text, nonfinite="reject")
            v = parse(text, nonfinite="defer")
            self.assertIs(v[0], V._NONFINITE)

    def test_long_integers_are_doubles_not_big_ints(self):
        # 300 digits is finite; int() on text would also hit the 4300-digit
        # limit on 3.11+ and not on 3.10.
        v = parse("[" + "1" + "0" * 299 + "]")
        self.assertEqual(v[0], 1e299)
        self.assertEqual(parse("[9007199254740993]")[0], 9007199254740992.0)
        self.assertEqual(parse("[1e-400]")[0], 0.0)

    def test_lone_surrogate_anywhere_is_rejected(self):
        for text in (
            '"\\ud800"',
            '"\\udc00"',
            '{"k":"\\ud800"}',
            '{"\\ud800":1}',
            '["a","\\ud800"]',
            '{"a":{"b":[{"c":{"d":"\\ud800"}}]}}',
            '"\\ude00\\ud83d"',        # reversed pair
            '"\\ud83d x"',
        ):
            with self.assertRaises(V._Reject, msg=text):
                parse(text)

    def test_valid_surrogate_pair_is_fine(self):
        self.assertEqual(parse('"\\ud83d\\ude00"'), "\U0001F600")
        self.assertEqual(parse('{"\\ud83d\\ude00":1}'), {"\U0001F600": 1})

    def test_duplicate_keys_follow_the_policy(self):
        text = '{"a":1,"a":2}'
        self.assertEqual(parse(text, dup="last"), {"a": 2})
        for t in (text, '{"x":{"a":1,"a":2}}', '[{"a":1,"\\u0061":2}]'):
            with self.assertRaises(V._Reject, msg=t):
                parse(t, dup="reject")
        self.assertEqual(parse('{"a":1,"b":2}', dup="reject"), {"a": 1, "b": 2})
        self.assertEqual(parse('{"x":{"a":1},"y":{"a":2}}', dup="reject"), {"x": {"a": 1}, "y": {"a": 2}})

    def test_depth_limit_is_128(self):
        self.assertEqual(parse("[" * 128 + "]" * 128), parse("[" * 128 + "]" * 128))
        with self.assertRaises(V._Reject):
            parse("[" * 129 + "]" * 129)
        with self.assertRaises(V._Reject):
            parse('{"a":' * 129 + "1" + "}" * 129)
        # brackets inside strings do not count
        self.assertEqual(parse('["' + "[" * 500 + '"]'), ["[" * 500])

    def test_extreme_depth_is_a_rejection_not_a_crash(self):
        for n in (1000, 10000, 200000):
            with self.assertRaises(V._Reject):
                parse("[" * n + "]" * n)
            with self.assertRaises(V._Reject):
                parse("[" * n)  # not even closed

    def test_unknown_policy_values_are_a_programming_error(self):
        with self.assertRaises(ValueError):
            V.parse_json(b"{}", dup="first", nonfinite="reject")
        with self.assertRaises(ValueError):
            V.parse_json(b"{}", dup="last", nonfinite="ignore")


if __name__ == "__main__":
    unittest.main()
