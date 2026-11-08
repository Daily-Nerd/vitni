"""The declaration: exactly the gating atoms the verifier implements."""
import json
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._cli import run_cli
from ._paths import ROOT


class Declaration(unittest.TestCase):
    def test_exact_line(self):
        self.assertEqual(run_cli(["profiles"])[1], b'["alg:ES256","alg:EdDSA","canon:b64-strict","canon:jcs"]\n')
        self.assertEqual(V.PROFILES, ("alg:ES256", "alg:EdDSA", "canon:b64-strict", "canon:jcs"))

    def test_equals_the_catalog_gating_atoms(self):
        catalog = json.loads((ROOT / "conformance" / "profiles.json").read_text(encoding="utf-8"))
        gating = sorted(a["id"] for a in catalog["atoms"] if a["gating"])
        self.assertEqual(list(V.PROFILES), gating)

    def test_alg_atoms_derive_from_the_algorithm_table(self):
        self.assertEqual({p for p in V.PROFILES if p.startswith("alg:")}, {"alg:" + a for a in V.ALGS})

    def test_no_binding_atom_is_declared(self):
        # non-gating atoms can never change a vector's scope, so they carry no information
        self.assertFalse([p for p in V.PROFILES if p.startswith(("binding:", "cmd:"))])

    def test_declined_commands_are_real_protocol_commands(self):
        contract = (ROOT / "conformance" / "CONTRACT.md").read_text(encoding="utf-8")
        for command in V.DECLINED:
            self.assertIn("`" + command + "`", contract, command)


if __name__ == "__main__":
    unittest.main()
