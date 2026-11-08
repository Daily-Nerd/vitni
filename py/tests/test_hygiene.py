"""Properties of the shipped file itself: its pin, its contract text."""
import ast
import unittest

from ._paths import ROOT, VERIFIER


class GitAttributes(unittest.TestCase):
    def test_gitattributes_pins_lf(self):
        # A checkout with autocrlf must not change the bytes (and so the sha256)
        # that downstream vendors pin.
        lines = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        self.assertIn("py/vitni_verify.py text eol=lf", [l.strip() for l in lines])


class Docstring(unittest.TestCase):
    def doc(self):
        return ast.get_docstring(ast.parse(VERIFIER.read_text(encoding="utf-8")))

    def test_docstring_states_contract(self):
        doc = self.doc()
        self.assertIsNotNone(doc)
        for needle in (
            "R||S",
            "unsupported_profile",
            "editing this file changes its pinned sha256",
            "valid",
            "failed",
            "unable",
        ):
            self.assertIn(needle, doc)

    def test_docstring_has_no_version_or_date(self):
        text = VERIFIER.read_text(encoding="utf-8")
        version = (ROOT / "version.txt").read_text(encoding="utf-8").strip()
        self.assertNotIn(version, text)


if __name__ == "__main__":
    unittest.main()
