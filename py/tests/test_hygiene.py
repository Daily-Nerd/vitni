"""Properties of the shipped file itself: its pin, its contract text, and the
single-owner rule (one function per decode site, so a second parse site cannot
appear without a test failing)."""
import ast
import json
import re
import sys
import unittest
import warnings

from ._paths import ROOT, VERIFIER

SOURCE = VERIFIER.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE, feature_version=(3, 10))

DECODERS = ("b64url_decode_strict", "b64std_decode_strict", "hex_decode_strict", "utf8_decode_strict")
BASE64_USERS = {"b64url_decode_strict", "b64std_decode_strict", "b64url_encode"}


def owners(match):
    """Top-level function name -> list of dotted call names accepted by `match`,
    attributing nested functions to their outermost def. Module-level calls are
    attributed to '<module>'."""
    found = {}

    def visit(node, owner):
        for child in ast.iter_child_nodes(node):
            name = owner
            if owner == "<module>" and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = child.name
            if isinstance(child, ast.Call):
                dotted = dotted_name(child.func)
                if dotted and match(dotted):
                    found.setdefault(name, []).append(dotted)
            visit(child, name)

    visit(TREE, "<module>")
    return found


def dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif parts:
        parts.append("?")
    else:
        return None
    return ".".join(reversed(parts))


def attribute_uses(module):
    """Function names that touch `module.<anything>` (call or not)."""
    found = set()

    def visit(node, owner):
        for child in ast.iter_child_nodes(node):
            name = owner
            if owner == "<module>" and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = child.name
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == module:
                found.add(name)
            visit(child, name)

    visit(TREE, "<module>")
    return found


def top_level_functions():
    return {n.name for n in TREE.body if isinstance(n, ast.FunctionDef)}


class GitAttributes(unittest.TestCase):
    def test_gitattributes_pins_lf(self):
        # A checkout with autocrlf must not change the bytes (and so the sha256)
        # that downstream vendors pin.
        lines = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        self.assertIn("py/vitni_verify.py text eol=lf", [l.strip() for l in lines])

    def test_file_has_no_crlf(self):
        self.assertNotIn(b"\r", VERIFIER.read_bytes())


class Docstring(unittest.TestCase):
    def test_docstring_states_contract(self):
        doc = ast.get_docstring(TREE)
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


class NoStamp(unittest.TestCase):
    def test_no_repo_version_release_marker_or_version_constant(self):
        version = (ROOT / "version.txt").read_text(encoding="utf-8").strip()
        self.assertNotIn(version, SOURCE)
        self.assertNotIn("release-please", SOURCE)
        assigned = {t.id for n in ast.walk(TREE) if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
        self.assertNotIn("__version__", assigned)
        # ADR-12: nothing consumes a protocol-version constant, so none exists.
        self.assertNotIn("IMPLEMENTS", assigned)

    def test_not_a_release_please_extra_file(self):
        config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
        for pkg in config["packages"].values():
            for extra in pkg.get("extra-files", []):
                path = extra if isinstance(extra, str) else extra.get("path", "")
                self.assertFalse(path.startswith("py/"), path)


class Text(unittest.TestCase):
    def test_no_em_dash(self):
        self.assertNotIn(chr(0x2014), SOURCE)

    def test_stdlib_only(self):
        mods = set()
        for n in ast.walk(TREE):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                self.assertEqual(n.level, 0)
                mods.add((n.module or "").split(".")[0])
        self.assertTrue(mods <= set(sys.stdlib_module_names), mods - set(sys.stdlib_module_names))
        self.assertTrue(mods)

    def test_no_third_party_crypto_named(self):
        self.assertIsNone(re.search(r"cryptography|ecdsa|nacl", SOURCE))

    def test_parses_as_python_310(self):
        ast.parse(SOURCE, feature_version=(3, 10))

    def test_line_budget(self):
        lines = SOURCE.count("\n")
        self.assertLess(lines, 800)
        if lines >= 700:
            warnings.warn(f"py/vitni_verify.py is {lines} lines (budget 800)")


class SingleOwner(unittest.TestCase):
    """Every external byte string enters through one strict decoder per format."""

    def test_the_decoders_exist(self):
        self.assertTrue(set(DECODERS) | {"parse_json", "b64url_encode"} <= top_level_functions())

    def test_only_parse_json_calls_json_loads(self):
        calls = owners(lambda d: d.startswith("json."))
        self.assertEqual(calls, {"parse_json": ["json.loads"]})

    def test_only_the_b64_functions_touch_base64(self):
        self.assertEqual(attribute_uses("base64"), BASE64_USERS)

    def test_only_utf8_decode_strict_decodes(self):
        self.assertEqual(set(owners(lambda d: d.endswith(".decode"))), {"utf8_decode_strict"})

    def test_only_hex_decode_strict_reads_hex(self):
        self.assertEqual(set(owners(lambda d: d.endswith(".fromhex") or d.startswith("binascii."))), {"hex_decode_strict"})

    def test_no_import_form_hides_a_use(self):
        for n in ast.walk(TREE):
            if isinstance(n, ast.ImportFrom):
                self.assertNotIn(n.module, ("json", "base64", "binascii"), "use `import x` so uses stay greppable")

    def test_parse_json_pins_every_lenient_default(self):
        (call,) = [c for c in ast.walk(TREE) if isinstance(c, ast.Call) and dotted_name(c.func) == "json.loads"]
        self.assertEqual({k.arg for k in call.keywords}, {"parse_constant", "parse_float", "parse_int", "object_pairs_hook"})
        # the argument is decoded text, never the raw bytes parameter
        self.assertIsInstance(call.args[0], ast.Name)
        self.assertNotEqual(call.args[0].id, "data")


class NoDer(unittest.TestCase):
    def test_no_function_parses_der(self):
        # ES256 is raw R||S only: no DER/ASN.1 helper may exist, not even unused.
        words = set()
        for n in ast.walk(TREE):
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                words |= set(n.name.lower().split("_"))
            elif isinstance(n, ast.Name):
                words |= set(n.id.lower().split("_"))
        self.assertFalse(words & {"der", "asn1", "asn", "dss"}, words & {"der", "asn1", "asn", "dss"})
        self.assertTrue(top_level_functions() >= {"_ecdsa_p256_verify"})


if __name__ == "__main__":
    unittest.main()
