"""Unit tests for the profile tagger (_profiles.py), the only place a vector's
`profiles` member is computed.

Run: uv run --no-project python conformance/vectors/test_profiles.py
(stdlib unittest only; no third-party dependency).
"""
import base64
import json
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))

import _profiles  # noqa: E402

CATALOG = json.loads((HERE.parent / "profiles.json").read_text())
ATOM_ID = re.compile(r"^[a-z0-9]+:[A-Za-z0-9._-]+$")


def vector(name):
    return json.loads((HERE / f"{name}.json").read_text())


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jws(header, payload):
    return ".".join([b64u(json.dumps(header).encode()), b64u(json.dumps(payload).encode()), "AAAA"])


class CatalogShape(unittest.TestCase):
    def test_fields_and_ids(self):
        ids = [a["id"] for a in CATALOG["atoms"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate atom id")
        for a in CATALOG["atoms"]:
            self.assertEqual(set(a), {"id", "section", "status", "gating"})
            self.assertRegex(a["id"], ATOM_ID)
            self.assertIsInstance(a["gating"], bool)

    def test_no_command_atoms(self):
        for a in CATALOG["atoms"]:
            self.assertFalse(a["id"].startswith("cmd:"), "cmd:* atoms are derived, never catalogued")

    def test_gating_set(self):
        gating = sorted(a["id"] for a in CATALOG["atoms"] if a["gating"])
        self.assertEqual(gating, ["alg:ES256", "alg:EdDSA", "canon:b64-strict", "canon:jcs"])


class AtomsForFixtures(unittest.TestCase):
    """spec S1.8: expectations on real vectors (binding atoms are informational)."""

    def gating(self, name):
        return [a for a in _profiles.atoms_for(vector(name)) if not a.startswith("binding:")]

    def test_verify_valid_es256(self):
        self.assertEqual(self.gating("verify-valid-es256"), ["alg:ES256", "canon:b64-strict", "canon:jcs"])
        self.assertIn("binding:mcp", _profiles.atoms_for(vector("verify-valid-es256")))

    def test_verify_valid_ed25519(self):
        self.assertIn("alg:EdDSA", self.gating("verify-valid-ed25519"))
        self.assertNotIn("alg:ES256", self.gating("verify-valid-ed25519"))

    def test_jcs_number(self):
        self.assertEqual(_profiles.atoms_for(vector("jcs-num-1e21")), ["canon:jcs"])

    def test_keygen(self):
        # keygen produces an Ed25519 key (alg:EdDSA) and its seed is a std-base64
        # member (canon:b64-strict), design 4.2. Spec S1.8 lists only alg:EdDSA;
        # the design rule wins because the seed decoder is exactly what the
        # keygen-seed-* vectors exercise.
        paths = sorted(HERE.glob("keygen-*.json"))
        self.assertTrue(paths)
        for p in paths:
            self.assertEqual(_profiles.atoms_for(json.loads(p.read_text())),
                             ["alg:EdDSA", "canon:b64-strict"], p.name)

    def test_local_binding(self):
        self.assertIn("binding:local", _profiles.atoms_for(vector("verify-local-valid")))

    def test_chain_collects_every_receipt(self):
        atoms = _profiles.atoms_for(vector("chain-valid-2hop"))
        self.assertTrue({"alg:ES256", "alg:EdDSA"} <= set(atoms), atoms)


class AtomsForRules(unittest.TestCase):
    def test_signing_key_alg_not_header_alg(self):
        keys = {"p": {"k": {"alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": "AA"}}}
        v = {"name": "x", "command": "verify",
             "input": {"signed_receipt": jws({"alg": "ES256", "kid": "k"}, {"performer_id": "p"}),
                       "keys": keys, "policy": None}}
        atoms = _profiles.atoms_for(v)
        self.assertIn("alg:EdDSA", atoms)
        self.assertNotIn("alg:ES256", atoms)

    def test_undecodable_or_unresolved_adds_no_alg(self):
        for signed in ("not-a-jws", "a.b", jws({"alg": "EdDSA", "kid": "nope"}, {"performer_id": "p"}), None, 5):
            v = {"name": "x", "command": "verify",
                 "input": {"signed_receipt": signed, "keys": {"p": {"k": {"alg": "EdDSA"}}}, "policy": None}}
            self.assertEqual(_profiles.atoms_for(v), ["canon:b64-strict", "canon:jcs"], signed)

    def test_registry_alg_outside_the_catalog_adds_nothing(self):
        keys = {"p": {"k": {"alg": "RS256"}}}
        v = {"name": "x", "command": "verify",
             "input": {"signed_receipt": jws({"alg": "RS256", "kid": "k"}, {"performer_id": "p"}),
                       "keys": keys, "policy": None}}
        self.assertEqual(_profiles.atoms_for(v), ["canon:b64-strict", "canon:jcs"])

    def test_unknown_binding_fails_loudly(self):
        keys = {"p": {"k": {"alg": "EdDSA"}}}
        v = {"name": "x", "command": "verify",
             "input": {"signed_receipt": jws({"alg": "EdDSA", "kid": "k"},
                                             {"performer_id": "p", "binding": "a2a"}),
                       "keys": keys, "policy": None}}
        with self.assertRaisesRegex(ValueError, "binding:a2a"):
            _profiles.atoms_for(v)

    def test_receipt_id_binding(self):
        v = {"name": "x", "command": "receipt-id", "input": {"receipt": {"binding": "local"}}}
        self.assertEqual(_profiles.atoms_for(v), ["binding:local", "canon:jcs"])

    def test_sse_jsonrpc_is_jcs_and_plain_sse_is_not(self):
        a = _profiles.atoms_for({"name": "x", "command": "sse-outputs-hash",
                                 "input": {"mode": "sse-jsonrpc", "raw_b64": "AA=="}})
        b = _profiles.atoms_for({"name": "x", "command": "sse-outputs-hash",
                                 "input": {"mode": "sse", "raw_b64": "AA=="}})
        self.assertEqual(a, ["canon:b64-strict", "canon:jcs"])
        self.assertEqual(b, ["canon:b64-strict"])

    def test_raw_stdin_forms_do_not_crash(self):
        for form in ({"input_raw": "{"}, {"input_raw_b64": "/w=="}):
            v = {"name": "x", "command": "digest", **form}
            self.assertIsInstance(_profiles.atoms_for(v), list)

    def test_never_emits_cmd_atoms_sorted_unique(self):
        for p in sorted(HERE.glob("*.json")):
            atoms = _profiles.atoms_for(json.loads(p.read_text()))
            self.assertEqual(atoms, sorted(set(atoms)), p.name)
            self.assertFalse([a for a in atoms if a.startswith("cmd:")], p.name)
            for a in atoms:
                self.assertIn(a, {c["id"] for c in CATALOG["atoms"]}, p.name)

    def test_unknown_command_has_no_atoms(self):
        self.assertEqual(_profiles.atoms_for({"name": "x", "command": "not-a-command", "input": {}}), [])


class Finalize(unittest.TestCase):
    def base(self):
        return {"name": "a", "command": "jcs", "input": {"value": 1}, "anchor": {"canonical_hex": "31"}}

    def test_profiles_goes_right_after_command(self):
        self.assertEqual(list(_profiles.finalize(self.base())),
                         ["name", "command", "profiles", "input", "anchor"])
        self.assertEqual(_profiles.finalize(self.base())["profiles"], ["canon:jcs"])

    def test_generator_cannot_supply_profiles(self):
        v = self.base()
        v["profiles"] = ["canon:jcs"]
        with self.assertRaisesRegex(ValueError, "profiles"):
            _profiles.finalize(v)

    def test_exactly_one_input_form(self):
        for bad in ({}, {"input": {}, "input_raw": "{}"}):
            v = {"name": "a", "command": "jcs", "anchor": {}, **bad}
            with self.assertRaisesRegex(ValueError, "exactly one"):
                _profiles.finalize(v)

    def test_write_is_deterministic_text(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "v.json"
            _profiles.write(p, self.base())
            first = p.read_text()
            _profiles.write(p, self.base())
            self.assertEqual(first, p.read_text())
            self.assertTrue(first.endswith("}\n"))
            self.assertEqual(json.loads(first)["profiles"], ["canon:jcs"])


if __name__ == "__main__":
    unittest.main()
