"""RFC 8785 output is unique: key order by UTF-16 code unit, ECMAScript number
text, explicit string escapes. Never the stdlib json writer."""
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._vectors import load_vectors, stdin_bytes


def canon(text, **kw):
    return V.jcs(V.parse_json(text.encode("utf-8"), dup="last", nonfinite=kw.get("nonfinite", "reject")))


class EsNumber(unittest.TestCase):
    TABLE = (
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (123456789012345680000.0, "123456789012345680000"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (4.35, "4.35"),
        (0.1 + 0.2, "0.30000000000000004"),
        (0.1, "0.1"),
        (-0.0, "0"),
        (0.0, "0"),
        (10.0, "10"),
        (100.0, "100"),
        (1.0, "1"),
        (9007199254740993.0, "9007199254740992"),
        (2.0 ** 53, "9007199254740992"),
        (-1.5, "-1.5"),
        (-1e21, "-1e+21"),
        (1.5e-7, "1.5e-7"),
        (123456.789, "123456.789"),
        (1e22, "1e+22"),
        (1e300, "1e+300"),
        (0.000001234, "0.000001234"),
        (1e16, "10000000000000000"),
        (1e-5, "0.00001"),
        (1.2345678901234568e20, "123456789012345680000"),
        (1.2345678901234568e21, "1.2345678901234568e+21"),
        (2.5e-7, "2.5e-7"),
    )

    def test_table(self):
        for f, want in self.TABLE:
            self.assertEqual(V._es_number(f), want, repr(f))

    def test_integers_and_big_literals_become_doubles(self):
        self.assertEqual(canon("[9007199254740993]"), b"[9007199254740992]")
        self.assertEqual(canon("[1e308]"), b"[1e+308]")
        self.assertEqual(canon("[" + "1" + "0" * 299 + "]"), b"[1e+299]")
        self.assertEqual(canon("[-0]"), b"[0]")
        self.assertEqual(canon("[1e-400]"), b"[0]")

    def test_overflow_has_no_canonical_form(self):
        with self.assertRaises(V._Reject):
            canon("[1e400]")  # reject policy: refused at parse
        v = V.parse_json(b"[1e400]", dup="last", nonfinite="defer")
        with self.assertRaises(V._NotCanonical):
            V.jcs(v)
        with self.assertRaises(V._NotCanonical):
            V.jcs(10 ** 400)
        with self.assertRaises(V._NotCanonical):
            V.jcs(float("inf"))
        with self.assertRaises(V._NotCanonical):
            V.jcs(float("nan"))


class Structure(unittest.TestCase):
    def test_key_order_is_utf16_code_units_not_code_points(self):
        keys = ["\U0001F600", "�", "\U00010000", "", "퟿"]
        got = V.jcs({k: 1 for k in keys})
        want_order = ["퟿", "\U00010000", "\U0001F600", "", "�"]
        want = ("{" + ",".join('"%s":1' % k for k in want_order) + "}").encode("utf-8")
        self.assertEqual(got, want)
        # code point order would put U+E000 before U+10000
        self.assertNotEqual(got, ("{" + ",".join('"%s":1' % k for k in sorted(keys)) + "}").encode("utf-8"))

    def test_sorted_and_compact(self):
        self.assertEqual(canon('{ "b" : [ 3 , 1 ] , "a" : { "z" : null , "y" : true } }'), b'{"a":{"y":true,"z":null},"b":[3,1]}')
        self.assertEqual(V.jcs({}), b"{}")
        self.assertEqual(V.jcs([]), b"[]")

    def test_bool_is_not_int(self):
        self.assertEqual(V.jcs([True, False, 1, 0]), b"[true,false,1,0]")
        self.assertEqual(V.jcs({"a": True}), b'{"a":true}')

    def test_string_escapes(self):
        cases = {
            '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t",
            "\x00": "\\u0000", "\x01": "\\u0001", "\x0b": "\\u000b", "\x1f": "\\u001f", "\x1a": "\\u001a",
            "\x7f": "\x7f", "/": "/", " ": " ", " ": " ", "é": "é", "\U0001F600": "\U0001F600",
        }
        for raw, esc in cases.items():
            self.assertEqual(V.jcs(raw), ('"' + esc + '"').encode("utf-8"), repr(raw))
        # every C0 control is escaped, lowercase hex
        for cp in range(0x20):
            out = V.jcs(chr(cp)).decode("ascii")
            self.assertNotIn(chr(cp), out)
            self.assertEqual(out, out.lower())

    def test_keys_are_escaped_like_strings(self):
        self.assertEqual(V.jcs({'a"\n': 1}), b'{"a\\"\\n":1}')


class Vectors(unittest.TestCase):
    def test_every_jcs_anchor(self):
        seen = 0
        for vec in load_vectors():
            if vec["command"] != "jcs" or "canonical_hex" not in vec.get("anchor", {}):
                continue
            doc = V.parse_json(stdin_bytes(vec), dup="reject", nonfinite="reject")
            got = V.jcs(doc["value"])
            self.assertEqual(got.hex(), vec["anchor"]["canonical_hex"], vec["_file"])
            self.assertEqual(len(got), vec["anchor"]["byte_len"], vec["_file"])
            seen += 1
        self.assertGreaterEqual(seen, 10)  # the loop must have run


if __name__ == "__main__":
    unittest.main()
