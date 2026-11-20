"""verify-batch: many independent verify questions in one call. Counterpart of
the Go and TS tests; all three pin the same contract (conformance/CONTRACT.md)."""
import json
import unittest

from . import _paths  # noqa: F401
import vitni_verify as V
from ._vectors import load_vectors

INVALID = b'{"error":"invalid_input"}'
MALFORMED = b'{"reason":"malformed","valid":false}'


def batch(*elements):
    return ('{"questions":[' + ",".join(elements) + "]}").encode()


def run(stdin, command="verify-batch"):
    return V.dispatch(command, lambda: stdin)


def deep(n):
    return "[" * n + "]" * n


class Elements(unittest.TestCase):
    def test_result_i_answers_question_i_alone_and_a_bad_element_touches_no_other(self):
        out = run(batch("{}", "5", "null", "[]", '{"signed_receipt":5}', '{"keys":[]}', '{"signed_receipt":"a.b.c","keys":{}}'))
        want = [MALFORMED, INVALID, INVALID, INVALID, INVALID, INVALID, MALFORMED]
        self.assertEqual(out, b'{"results":[' + b",".join(want) + b"]}")

    def test_empty_list(self):
        self.assertEqual(run(batch()), b'{"results":[]}')

    def test_the_batch_itself_must_be_questions_array(self):
        for stdin in (b"{}", b'{"questions":null}', b'{"questions":{}}', b'{"questions":"x"}', b'{"questions":5}',
                      b'{"Questions":[]}', b"[]", b"null", b""):
            self.assertEqual(run(stdin), INVALID, stdin)

    def test_duplicate_keys_are_last_wins(self):
        out = run(b'{"questions":[],"questions":[{"signed_receipt":5,"signed_receipt":null}]}')
        self.assertEqual(out, b'{"results":[' + MALFORMED + b"]}")


class Limit(unittest.TestCase):
    def test_65536_answers_and_one_more_is_batch_too_large(self):
        self.assertEqual(V.MAX_BATCH_QUESTIONS, 65536)
        build = lambda n: ('{"questions":[' + ",".join(["{}"] * n) + "]}").encode()
        self.assertEqual(len(json.loads(run(build(V.MAX_BATCH_QUESTIONS)))["results"]), V.MAX_BATCH_QUESTIONS)
        self.assertEqual(run(build(V.MAX_BATCH_QUESTIONS + 1)), b'{"error":"batch_too_large"}')


class TextFaults(unittest.TestCase):
    def test_a_text_fault_anywhere_fails_the_whole_batch(self):
        self.assertEqual(run(batch("{}", '{"x":"\\ud800"}')), INVALID)
        self.assertEqual(run(batch("{}", '{"x":1e400}')), INVALID)
        # elements sit two levels deeper than a lone verify input: depth 3 + n
        self.assertEqual(run(batch("{}", '{"x":' + deep(126) + "}")), INVALID)
        self.assertNotIn(b"error", run(batch('{"x":' + deep(125) + "}")))
        self.assertNotIn(b"error", run(('{"x":' + deep(127) + "}").encode(), "verify"))


class SharedPath(unittest.TestCase):
    def test_results_0_equals_verify_alone_for_every_structured_verify_vector(self):
        checked = 0
        for vec in load_vectors():
            if vec["command"] != "verify" or "input" not in vec:
                continue
            element = json.dumps(vec["input"])
            alone = run(element.encode(), "verify")
            self.assertEqual(run(batch(element)), b'{"results":[' + alone + b"]}", vec["_file"])
            checked += 1
        self.assertGreater(checked, 100)


if __name__ == "__main__":
    unittest.main()
