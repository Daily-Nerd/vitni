"""Edges that are reachable but were never asserted: each test pins the exact
verdict or error, at the primitive and through the public entry point."""
import runpy
import sys
import unittest
from unittest import mock

from . import _paths  # noqa: F401
import vitni_verify as V
from ._jws import KID, PERFORMER, jws, registry
from ._paths import VERIFIER
from .test_cli import PROFILES_LINE, fake_streams, main_in_process

# An Ed25519 key whose y = 2 has no x on the curve: x^2 is not a square mod p.
OFF_CURVE_X = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class OffCurveEd25519Key(unittest.TestCase):
    def test_recover_x_returns_none_when_x_squared_is_not_a_square(self):
        self.assertIsNone(V._ed_recover_x(2, 0))
        self.assertIsNone(V._ed_recover_x(2, 1))

    def test_verify_primitive_is_false_for_the_off_curve_key(self):
        pub = (2).to_bytes(32, "little")
        self.assertIs(V._ed25519_verify(pub, bytes(64), b"m"), False)

    def test_verify_command_answers_bad_signature(self):
        keys = registry(x=OFF_CURVE_X)
        self.assertEqual(V.verify(jws(), keys, None), {"reason": "bad_signature", "valid": False})


class NullRequiredMember(unittest.TestCase):
    def test_a_required_member_present_as_null_is_invalid_input(self):
        for command, stdin in (
            ("hashstring", b'{"algo":null,"digest_hex":"00"}'),
            ("hashstring", b'{"algo":"sha256","digest_hex":null}'),
            ("digest", b'{"bytes_b64":null}'),
            ("receipt-id", b'{"receipt":null}'),
        ):
            rc, out, err = main_in_process([command], stdin)
            self.assertEqual((rc, out, err), (0, b'{"error":"invalid_input"}\n', b""), (command, stdin))

    def test_every_shape_member_is_required_so_the_table_carries_no_required_flag(self):
        for command, members in V._SHAPES.items():
            for member in members:
                self.assertEqual(len(member), 2, (command, member))


class CommandLine(unittest.TestCase):
    def test_no_command_at_all_is_missing_command(self):
        self.assertEqual(V.main_output([], lambda: self.fail("stdin must not be read")), b'{"error":"missing_command"}')

    def test_profiles_in_process_never_reads_stdin(self):
        def no_stdin():
            self.fail("stdin must not be read")
        self.assertEqual(V.main_output(["profiles"], no_stdin) + b"\n", PROFILES_LINE)

    def test_run_as_a_script_exits_zero_after_one_line(self):
        sin, sout, serr, out, err = fake_streams()
        with sin, sout, serr, mock.patch.object(sys, "argv", [str(VERIFIER), "profiles"]):
            with self.assertRaises(SystemExit) as cm:
                runpy.run_path(str(VERIFIER), run_name="__main__")
            sys.stdout.flush()
        self.assertEqual((cm.exception.code, out.getvalue(), err.getvalue()), (0, PROFILES_LINE, b""))


class LoneSurrogateInJcs(unittest.TestCase):
    def test_a_lone_surrogate_value_is_not_canonical(self):
        with self.assertRaises(V._NotCanonical) as cm:
            V.jcs("\ud800")
        self.assertEqual(str(cm.exception), "lone surrogate")

    def test_a_lone_surrogate_key_is_not_canonical(self):
        with self.assertRaises(V._NotCanonical) as cm:
            V.jcs({"\ud800": 1})
        self.assertEqual(str(cm.exception), "lone surrogate in key")


if __name__ == "__main__":
    unittest.main()
