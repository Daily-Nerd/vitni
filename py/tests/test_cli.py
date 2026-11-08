"""The CLI contract: one JCS line, exit 0 on every handled path, nothing else on
stdout, the same command resolution order as Go and TS."""
import io
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from . import _paths  # noqa: F401
import vitni_verify as V
from ._cli import run_cli
from ._paths import VERIFIER
from ._vectors import load_vectors, stdin_bytes

PROFILES_LINE = b'["alg:ES256","alg:EdDSA","canon:b64-strict","canon:jcs"]\n'
DECLINED = ["a2a-artifact-hash", "cost-canon", "keygen", "sign", "sse-outputs-hash", "verify-chain"]


def fake_streams(stdin=b""):
    out, err = io.BytesIO(), io.BytesIO()
    return (
        mock.patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")),
        mock.patch.object(sys, "stdout", io.TextIOWrapper(out, encoding="utf-8", newline="")),
        mock.patch.object(sys, "stderr", io.TextIOWrapper(err, encoding="utf-8", newline="")),
        out, err,
    )


def main_in_process(argv, stdin=b""):
    sin, sout, serr, out, err = fake_streams(stdin)
    with sin, sout, serr:
        rc = V.main(argv)
        sys.stdout.flush()
    return rc, out.getvalue(), err.getvalue()


class Shape(unittest.TestCase):
    def test_one_line_exit_zero_nothing_else(self):
        for command, stdin in (
            ("jcs", b'{"value":{"b":[1,2]}}'), ("digest", b'{"bytes_b64":"aGk="}'), ("verify", b"{}"),
            ("jcs", b"not json"), ("jcs", b""), ("hashstring", b"[]"), ("receipt-id", b'{"receipt":{}}'),
        ):
            rc, out, err = run_cli([command], stdin)
            self.assertEqual(rc, 0, command)
            self.assertTrue(out.endswith(b"\n") and out.count(b"\n") == 1, (command, out))
            self.assertNotIn(b"\r", out)
            self.assertEqual(V.jcs(json.loads(out)) + b"\n", out)  # the line is itself JCS
            self.assertEqual(err, b"", command)

    def test_known_answers(self):
        self.assertEqual(run_cli(["jcs"], b'{"value":{"b":1,"a":[]}}')[1], b'{"byte_len":13,"canonical_hex":"' + b'{"a":[],"b":1}'.hex().encode() + b'"}\n')
        self.assertEqual(run_cli(["digest"], b'{"bytes_b64":"aGVsbG8="}')[1], b'{"hashstr":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA"}\n')

    def test_stdout_is_binary_and_never_translated(self):
        rc, out, err = main_in_process(["jcs"], '{"value":"\U0001F600"}'.encode("utf-8"))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["canonical_hex"], '"\U0001F600"'.encode("utf-8").hex())
        self.assertTrue(out.endswith(b"}\n") and b"\r" not in out)

    def test_main_uses_the_buffers(self):
        src = VERIFIER.read_text(encoding="utf-8")
        self.assertIn("sys.stdout.buffer.write", src)
        self.assertIn("sys.stdin.buffer", src)
        self.assertNotIn("print(", src)


class Resolution(unittest.TestCase):
    def test_missing_and_unknown_command(self):
        self.assertEqual(run_cli([], b'{"value":1}')[1], b'{"error":"missing_command"}\n')
        self.assertEqual(run_cli(["bogus"], b'{"value":1}')[1], b'{"error":"unsupported_command"}\n')
        self.assertEqual(run_cli(["JCS"], b'{"value":1}')[1], b'{"error":"unsupported_command"}\n')  # exact, case-sensitive
        self.assertEqual(run_cli(["bogus"], b"\xff\xfe not even json")[1], b'{"error":"unsupported_command"}\n')  # resolves before any parse

    def test_declined_commands_never_read_stdin(self):
        for command in DECLINED:
            proc = subprocess.Popen([sys.executable, "-I", str(VERIFIER), command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                # stdin stays open and empty: a read would block until the timeout
                self.assertEqual(proc.wait(timeout=20), 0, command)
                out = proc.stdout.read()
            finally:
                proc.kill()
                for f in (proc.stdin, proc.stdout, proc.stderr):
                    f.close()
            self.assertEqual(out, b'{"error":"unsupported_profile","profile":"cmd:' + command.encode() + b'"}\n')

    def test_declined_is_not_unsupported_command(self):
        for command in DECLINED:
            self.assertNotEqual(run_cli([command], b"garbage")[1], b'{"error":"unsupported_command"}\n')

    def test_profiles_line_and_no_stdin(self):
        self.assertEqual(run_cli(["profiles"], b"")[1], PROFILES_LINE)
        self.assertEqual(run_cli(["profiles"], b"\xff junk")[1], PROFILES_LINE)
        proc = subprocess.Popen([sys.executable, "-I", str(VERIFIER), "profiles"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            self.assertEqual(proc.wait(timeout=20), 0)
            self.assertEqual(proc.stdout.read(), PROFILES_LINE)
        finally:
            proc.kill()
            proc.stdin.close()
            proc.stdout.close()

    def test_command_sets_are_derived_from_the_vectors(self):
        # no copy of the list: what the vectors exercise is what must exist
        wanted = {v["command"] for v in load_vectors() if v["anchor"].get("error") != "unsupported_command"}
        self.assertEqual((set(V.COMMANDS) - {"profiles"}) | set(V.DECLINED), wanted)
        self.assertFalse(set(V.COMMANDS) & set(V.DECLINED))
        self.assertEqual(sorted(V.DECLINED), DECLINED)


class LastResort(unittest.TestCase):
    def test_an_unexpected_exception_prints_internal_error_not_a_traceback(self):
        with mock.patch.object(V, "dispatch", side_effect=RuntimeError("boom")):
            rc, out, err = main_in_process(["jcs"], b"{}")
        self.assertEqual((rc, out, err), (0, b'{"error":"internal_error"}\n', b""))

    def test_a_bug_inside_a_handler_is_internal_error_not_a_verdict(self):
        with mock.patch.dict(V.COMMANDS, {"jcs": mock.Mock(side_effect=ZeroDivisionError)}):
            rc, out, err = main_in_process(["jcs"], b'{"value":1}')
        self.assertEqual((rc, out), (0, b'{"error":"internal_error"}\n'))

    def test_reading_stdin_failing_is_internal_error(self):
        broken = mock.Mock(side_effect=OSError("closed"))
        self.assertEqual(V.main_output(["jcs"], broken), b'{"error":"internal_error"}')


class Isolation(unittest.TestCase):
    def test_a_planted_json_module_in_cwd_is_not_imported(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("json.py", "hashlib.py", "base64.py", "re.py"):
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write("raise SystemExit('hijacked')\n")
            rc, out, err = run_cli(["jcs"], b'{"value":[1]}', cwd=d)
        self.assertEqual((rc, out), (0, b'{"byte_len":3,"canonical_hex":"5b315d"}\n'))
        self.assertEqual(err, b"")


class Fuzz(unittest.TestCase):
    ALLOWED = {
        "jcs": [{"error"}, {"byte_len", "canonical_hex"}],
        "digest": [{"error"}, {"hashstr"}],
        "hashstring": [{"error"}, {"hashstr"}],
        "receipt-id": [{"error"}, {"canonical_hex", "receipt_id"}],
        "verify": [{"error"}, {"reason", "valid"}],
    }
    CODES = {"invalid_input", "receipt_id_must_be_absent"}

    def check(self, command, data):
        out = V.dispatch(command, lambda: data)
        self.assertTrue(isinstance(out, bytes) and b"\n" not in out, (command, data[:40]))
        doc = json.loads(out)
        self.assertIn(set(doc), self.ALLOWED[command], (command, data[:40], out))
        if "error" in doc:
            self.assertIn(doc["error"], self.CODES, (command, data[:40], out))
        if "reason" in doc:
            self.assertIn(doc["reason"], {"ok", "malformed", "header_key_material", "unknown_key", "revoked_key",
                                          "alg_not_allowed", "bad_signature", "non_canonical_payload", "context_mismatch"})
        return doc

    def test_random_bytes_never_raise_and_stay_in_the_allowed_codes(self):
        rng = random.Random(2026)
        fragments = [b'{"value":', b'{"receipt":', b'{"bytes_b64":"', b'{"signed_receipt":"', b'{"algo":"sha2-256","digest_hex":"',
                     b"\\ud800", b"1e999", b"[[[[", b"null", b'"}', b"\xff", b"\xef\xbb\xbf", b"\x00", b"{}"]
        for i in range(2000):
            if i % 2:
                data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 64)))
            else:
                data = b"".join(rng.choice(fragments) for _ in range(rng.randrange(1, 6)))
            for command in self.ALLOWED:
                self.check(command, data)

    def test_mutation_matrix_over_every_in_scope_vector(self):
        n = 0
        for vec in load_vectors():
            if vec["command"] not in self.ALLOWED:
                continue
            data = stdin_bytes(vec)
            muts = [data[:k] for k in range(0, len(data), max(1, len(data) // 9))]
            muts += [data + b"\x00", data + b" x", b"\xef\xbb\xbf" + data, b" \t\r\n" + data + b"\n", data.replace(b'"', b"'", 1)]
            muts += [data.replace(b'"', b'"\\ud800', 1), data.replace(b"{", b"[", 1), data[::-1]]
            for pos in range(0, len(data), max(1, len(data) // 7)):
                muts.append(data[:pos] + bytes([data[pos] ^ 0x41]) + data[pos + 1:])
            for m in muts:
                self.check(vec["command"], m)
                n += 1
        self.assertGreater(n, 1500)


if __name__ == "__main__":
    unittest.main()
