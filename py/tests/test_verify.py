"""The verify pipeline: CONTRACT steps 1 to 8, first failing step wins."""
import itertools
import json
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._jws import KID, PERFORMER, b64u, jws, payload_dict, registry
from ._vectors import load_vectors, stdin_bytes

STEPS = [
    "malformed", "header_key_material", "unknown_key", "revoked_key",
    "alg_not_allowed", "bad_signature", "non_canonical_payload", "context_mismatch",
]


def verdict(r):
    return r["reason"]


def base_case():
    return {
        "header": {"alg": "EdDSA", "kid": KID},
        "payload": V.jcs(payload_dict()),
        "drop_key": False,
        "status": "active",
        "policy": {"expected_binding": None, "expected_method": None},
        "jws_override": None,
        "tamper_sig": False,
    }


def build(case):
    if case["jws_override"]:
        return case["jws_override"]
    token = jws(case["header"], case["payload"])
    if case["tamper_sig"]:
        h, p, s = token.split(".")
        token = ".".join((h, p, b64u(bytes(64))))
    return token


# One injector per step: after it runs, THAT step fails (and nothing earlier does).
def inj_malformed(c):
    c["jws_override"] = "only.two"


def inj_key_material(c):
    c["header"] = dict(c["header"], jwk={"kty": "OKP"})


def inj_unknown_key(c):
    c["drop_key"] = True


def inj_revoked(c):
    c["status"] = "revoked"


def inj_alg(c):
    c["header"] = dict(c["header"], alg="ES256")


def inj_bad_sig(c):
    c["tamper_sig"] = True


def inj_noncanonical(c):
    c["payload"] = b" " + c["payload"]


def inj_context(c):
    c["policy"] = {"expected_binding": "a2a", "expected_method": None}


INJECTORS = [inj_malformed, inj_key_material, inj_unknown_key, inj_revoked, inj_alg, inj_bad_sig, inj_noncanonical, inj_context]


def run_case(case):
    keys = {} if case["drop_key"] else registry(status=case["status"])
    return V.verify(build(case), keys, case["policy"])


class Baseline(unittest.TestCase):
    def test_a_valid_receipt_is_ok(self):
        self.assertEqual(run_case(base_case()), {"reason": "ok", "valid": True})

    def test_each_injector_alone_fails_exactly_its_step(self):
        for step, inject in zip(STEPS, INJECTORS):
            case = base_case()
            inject(case)
            self.assertEqual(verdict(run_case(case)), step, step)
            self.assertIs(run_case(case)["valid"], False)


class StepOrder(unittest.TestCase):
    def test_every_pair_of_failures_reports_the_earlier_step(self):
        for i, j in itertools.combinations(range(8), 2):
            case = base_case()
            INJECTORS[i](case)
            INJECTORS[j](case)
            self.assertEqual(verdict(run_case(case)), STEPS[i], (STEPS[i], STEPS[j]))

    def test_all_failures_at_once_is_the_first_step(self):
        case = base_case()
        for inject in INJECTORS:
            inject(case)
        self.assertEqual(verdict(run_case(case)), "malformed")


class OutputShape(unittest.TestCase):
    def test_keys_and_bool(self):
        for case in (base_case(), dict(base_case(), drop_key=True)):
            r = run_case(case)
            self.assertEqual(sorted(r), ["reason", "valid"])
            self.assertIn(r["valid"], (True, False))
            self.assertIs(type(r["valid"]), bool)
            self.assertIsInstance(r["reason"], str)
        self.assertEqual(V.jcs(run_case(base_case())), b'{"reason":"ok","valid":true}')


class Segments(unittest.TestCase):
    def verdict_of(self, token):
        return verdict(V.verify(token, registry(), None))

    def test_structure(self):
        good = jws()
        h, p, s = good.split(".")
        for token in ("", "a", "a.b", f"{h}.{p}", f"{h}.{p}.{s}.", f"{h}.{p}.{s}.x", "..", f"{h}..{s}", f".{p}.{s}"):
            self.assertEqual(self.verdict_of(token), "malformed", token)

    def test_alphabet_whitespace_padding_and_length(self):
        h, p, s = jws().split(".")
        for bad in (s + "=", s[:-1] + "+", s[:-1] + "/", s[:10] + "\n" + s[10:], s[:10] + "\r" + s[10:], s + " ", " " + s, s[:-1] + "é"):
            self.assertEqual(self.verdict_of(f"{h}.{p}.{bad}"), "malformed", repr(bad))
            self.assertEqual(self.verdict_of(f"{bad}.{p}.{s}"), "malformed", repr(bad))
            self.assertEqual(self.verdict_of(f"{h}.{bad}.{s}"), "malformed", repr(bad))

    def test_a_well_formed_signature_of_the_wrong_length_is_bad_signature(self):
        h, p, s = jws().split(".")
        for sig in (b64u(bytes(65)), b64u(bytes(63)), b64u(bytes(3)), ""):
            self.assertEqual(self.verdict_of(f"{h}.{p}.{sig}"), "bad_signature", sig)

    def test_trailing_bits_are_malformed_for_segments(self):
        h, p, s = jws().split(".")
        last = s[-1]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        # 64 raw bytes -> 86 chars, the last char carries 2 trailing bits that must be 0
        flipped = alphabet[(alphabet.index(last) + 1) % 64]
        self.assertEqual(self.verdict_of(f"{h}.{p}.{s[:-1] + flipped}"), "malformed")

    def test_trailing_bits_in_key_coordinates_are_bad_signature(self):
        token = jws()
        x = registry()[PERFORMER][KID]["x"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        flipped = x[:-1] + alphabet[(alphabet.index(x[-1]) + 1) % 64]
        keys = registry(x=flipped)
        self.assertEqual(verdict(V.verify(token, keys, None)), "bad_signature")


class HeaderAndPayload(unittest.TestCase):
    def run_with(self, header=None, payload=None, keys=None, policy=None):
        token = jws(header, payload)
        return verdict(V.verify(token, registry() if keys is None else keys, policy))

    def test_b64_rules(self):
        base = {"alg": "EdDSA", "kid": KID}
        self.assertEqual(self.run_with(dict(base, b64=True)), "ok")
        for bad in (False, None, 0, 1, "true", "false", [], {}, 1.0):
            self.assertEqual(self.run_with(dict(base, b64=bad)), "malformed", repr(bad))

    def test_text_policy_in_header_and_payload(self):
        header = b'{"alg":"EdDSA","kid":"k-1"}'
        for hb in (b"\xef\xbb\xbf" + header, b'{"alg":"EdDSA","kid":"k-1\xff"}', b'{"alg":"EdDSA","kid":"\\ud800"}',
                   b"[]", b"null", b"5", b'"s"', b"", header + b"x", b"[" * 129 + b"]" * 129):
            self.assertEqual(self.run_with(hb), "malformed", repr(hb[:20]))
        canon = V.jcs(payload_dict())
        for pb in (b"\xef\xbb\xbf" + canon, canon + b" x", b"[]", b"null", b"", b'{"performer_id":"\\ud800"}',
                   b'{"a":' * 129 + b"1" + b"}" * 129):
            self.assertEqual(self.run_with(None, pb), "malformed", repr(pb[:20]))

    def test_header_tolerates_duplicates_and_nonfinite_but_payload_does_not(self):
        h = b'{"alg":"EdDSA","kid":"k-1","kid":"k-1","x":1e400}'
        self.assertEqual(self.run_with(h), "ok")
        dup_kid = b'{"alg":"EdDSA","kid":"nope","kid":"k-1"}'
        self.assertEqual(self.run_with(dup_kid), "ok")  # last wins
        # payload: parsed leniently, then step 7 fails because the bytes are not canonical
        self.assertEqual(self.run_with(None, b'{"binding":"mcp","method":"mcp:echo","performer_id":"srv-test","v":"vitni/0.2","v":"vitni/0.2"}'),
                         "non_canonical_payload")
        self.assertEqual(self.run_with(None, b'{"binding":"mcp","ext":{"n":1e400},"method":"mcp:echo","performer_id":"srv-test","v":"vitni/0.2"}'),
                         "non_canonical_payload")
        self.assertEqual(self.run_with(None, b'{"binding":"mcp","method":"mcp:echo","performer_id":"srv-test","v":"vitni/0.2","z":1.0}'),
                         "non_canonical_payload")

    def test_forbidden_header_members(self):
        for member in ("jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256"):
            self.assertEqual(self.run_with({"alg": "EdDSA", "kid": KID, member: 1}), "header_key_material", member)
        self.assertEqual(self.run_with({"alg": "EdDSA", "kid": KID, "JWK": 1}), "ok")  # exact names

    def test_unknown_key_cases(self):
        for header, payload in (
            ({"alg": "EdDSA"}, None),                       # no kid
            ({"alg": "EdDSA", "kid": 5}, None),
            ({"alg": "EdDSA", "kid": "other"}, None),
            (None, V.jcs(payload_dict(performer_id="nobody"))),
            (None, V.jcs({"binding": "mcp"})),              # no performer_id
            (None, V.jcs(payload_dict(performer_id=7))),
        ):
            self.assertEqual(self.run_with(header, payload), "unknown_key", (header, payload))
        self.assertEqual(self.run_with(None, None, keys={PERFORMER: None}), "unknown_key")
        self.assertEqual(self.run_with(None, None, keys={PERFORMER: {KID: None}}), "unknown_key")
        # an empty entry exists (it is not absent): it fails at the alg binding, as in Go and TS
        self.assertEqual(self.run_with(None, None, keys={PERFORMER: {KID: {}}}), "alg_not_allowed")
        self.assertEqual(self.run_with(None, None, keys={PERFORMER: {}}), "unknown_key")
        self.assertEqual(verdict(V.verify(jws(), None, None)), "unknown_key")
        self.assertEqual(self.run_with(None, None, keys={}), "unknown_key")

    def test_prototype_names_are_ordinary_unknown_keys(self):
        for name in ("__proto__", "constructor", "toString", "hasOwnProperty"):
            self.assertEqual(self.run_with({"alg": "EdDSA", "kid": name}), "unknown_key", name)
            token = jws(None, V.jcs(payload_dict(performer_id=name)))
            self.assertEqual(verdict(V.verify(token, registry(), None)), "unknown_key", name)

    def test_prototype_names_are_pinned_by_shared_vectors(self):
        # the guard every implementation shares: the vectors, not a Python-only list
        wanted = {"verify/key-proto-name", "verify/key-constructor-name", "verify/key-tostring-name",
                  "verify/key-proto-performer", "verify/key-own-proto-name"}
        found = {v["name"]: v for v in load_vectors() if v["name"] in wanted}
        self.assertEqual(set(found), wanted)
        for vec in found.values():
            got = V.dispatch("verify", lambda vec=vec: stdin_bytes(vec))
            self.assertEqual({k: v for k, v in json.loads(got).items()}, vec["anchor"], vec["_file"])

    def test_revoked_only_for_the_exact_string(self):
        self.assertEqual(self.run_with(keys=registry(status="revoked")), "revoked_key")
        for status in ("Revoked", "REVOKED", "revoked ", "active", "", None):
            self.assertEqual(self.run_with(keys=registry(status=status)), "ok", repr(status))

    def test_alg_rules_and_key_type_binding(self):
        ok = {"alg": "EdDSA", "kid": KID}
        for header in ({"kid": KID}, {"alg": "none", "kid": KID}, {"alg": "", "kid": KID}, {"alg": 5, "kid": KID},
                       {"alg": "ES256", "kid": KID}, {"alg": "eddsa", "kid": KID}):
            self.assertEqual(self.run_with(header), "alg_not_allowed", header)
        # registry alg outside the table, even when the header agrees
        self.assertEqual(self.run_with({"alg": "RS256", "kid": KID}, keys=registry(alg="RS256")), "alg_not_allowed")
        self.assertEqual(self.run_with({"alg": "none", "kid": KID}, keys=registry(alg="none")), "alg_not_allowed")
        # kty/crv must be the ones the alg requires; missing or null fails
        for override in ({"kty": "EC"}, {"kty": "RSA"}, {"kty": None}, {"crv": "P-256"}, {"crv": "Ed448"}, {"crv": None}):
            self.assertEqual(self.run_with(ok, keys=registry(**override)), "alg_not_allowed", override)
        keys = registry()
        del keys[PERFORMER][KID]["kty"]
        self.assertEqual(self.run_with(ok, keys=keys), "alg_not_allowed")
        # a revoked key stays revoked even with a bad kty (step 4 before step 5c)
        self.assertEqual(self.run_with(ok, keys=registry(kty="EC", status="revoked")), "revoked_key")

    def test_key_material_problems_are_bad_signature(self):
        for override in ({"x": ""}, {"x": None}, {"x": "AAAA"}, {"x": registry()[PERFORMER][KID]["x"] + "="},
                         {"x": "+" * 43}, {"x": "A" * 44}, {"x": 5}):
            keys = registry()
            keys[PERFORMER][KID].update(override)
            if override["x"] == 5:
                self.assertEqual(V.verify(jws(), keys, None), {"error": "invalid_input"})
                continue
            self.assertEqual(self.run_with(keys=keys), "bad_signature", override)

    def test_policy(self):
        for policy, want in (
            (None, "ok"), ({}, "ok"),
            ({"expected_binding": "mcp"}, "ok"), ({"expected_binding": "a2a"}, "context_mismatch"),
            ({"expected_method": "mcp:echo"}, "ok"), ({"expected_method": "mcp:other"}, "context_mismatch"),
            ({"expected_binding": None, "expected_method": None}, "ok"),
            ({"expected_binding": "mcp", "expected_method": "mcp:other"}, "context_mismatch"),
            ({"expected_binding": ""}, "context_mismatch"),
        ):
            self.assertEqual(self.run_with(policy=policy), want, policy)


class Shape(unittest.TestCase):
    """A Python caller gets the same typing the CLI applies: invalid_input, never a verdict."""

    def test_wrong_types_are_invalid_input(self):
        token = jws()
        bad = [
            (5, registry(), None), (1.5, None, None), ([], None, None), ({}, None, None), (True, None, None),
            (token, 5, None), (token, [], None), (token, "keys", None), (token, 1.5, None),
            (token, {PERFORMER: 5}, None), (token, {PERFORMER: []}, None), (token, {PERFORMER: {KID: 5}}, None),
            (token, {PERFORMER: {KID: []}}, None), (token, {"other": {"k": "str"}}, None),
            (token, {PERFORMER: {KID: {"x": 5}}}, None), (token, {PERFORMER: {KID: {"kty": True}}}, None),
            (token, {PERFORMER: {KID: {"status": []}}}, None), (token, {PERFORMER: {KID: {"alg": 1.0}}}, None),
            (token, registry(), 5), (token, registry(), []), (token, registry(), "p"),
            (token, registry(), {"expected_binding": 5}), (token, registry(), {"expected_method": []}),
        ]
        for args in bad:
            self.assertEqual(V.verify(*args), {"error": "invalid_input"}, args)

    def test_absent_and_null_members(self):
        self.assertEqual(V.verify(None), {"reason": "malformed", "valid": False})
        self.assertEqual(V.verify(None, 5), {"error": "invalid_input"})  # typing is judged before the receipt
        self.assertEqual(verdict(V.verify(jws())), "unknown_key")
        self.assertEqual(verdict(V.verify(jws(), None, None)), "unknown_key")
        # unknown members anywhere are ignored
        keys = registry()
        keys[PERFORMER][KID]["rpId"] = [1, 2]
        keys[PERFORMER][KID]["origins"] = {"a": 1}
        keys["extra"] = None
        self.assertEqual(verdict(V.verify(jws(), keys, {"expected_binding": None, "other": 5})), "ok")


def flip_char(s, i):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    c = s[i]
    return s[:i] + (alphabet[(alphabet.index(c) + 1) % 64] if c in alphabet else "A") + s[i + 1:]


class MutationFuzz(unittest.TestCase):
    """Change every character of every segment of two receipts (one Ed25519, one
    ES256, taken from the conformance vectors): valid only for the original."""

    def receipts(self):
        out = []
        for name in ("verify/valid-ed25519", "verify/valid-es256"):
            vec = [v for v in load_vectors() if v["name"] == name][0]
            out.append((vec["input"]["signed_receipt"], vec["input"]["keys"], vec["input"]["policy"]))
        return out

    def test_valid_only_for_the_unmodified_receipt(self):
        for token, keys, policy in self.receipts():
            self.assertEqual(V.verify(token, keys, policy), {"reason": "ok", "valid": True})
            n = 0
            for i in range(len(token)):
                if token[i] == ".":
                    continue
                for mutated in (flip_char(token, i), token[:i] + "!" + token[i + 1:]):
                    r = V.verify(mutated, keys, policy)
                    self.assertEqual(sorted(r), ["reason", "valid"], (i, mutated[:30]))
                    self.assertIs(r["valid"], False, (i, r))
                    n += 1
            self.assertGreater(n, 1000)
        # truncations and extensions
        token, keys, policy = self.receipts()[0]
        for cut in range(0, len(token), 37):
            self.assertIs(V.verify(token[:cut], keys, policy)["valid"], False)


class Vectors(unittest.TestCase):
    def test_every_verify_vector_with_a_verdict_anchor(self):
        n = 0
        for vec in load_vectors():
            if vec["command"] != "verify" or "valid" not in vec["anchor"]:
                continue
            doc = V.parse_json(stdin_bytes(vec), dup="last", nonfinite="reject")
            got = V.verify(doc.get("signed_receipt"), doc.get("keys"), doc.get("policy"))
            self.assertEqual(got, vec["anchor"], vec["_file"])
            n += 1
        self.assertGreaterEqual(n, 90)


if __name__ == "__main__":
    unittest.main()
