/**
 * verify-batch: many independent verify questions in one call (CONTRACT.md).
 *
 * Input  { questions: [ <a verify input>, ... ] }
 * Output { results: [ <what verify prints for that question alone>, ... ] }
 *
 * `verifyAnswer` is the single owner of "the answer to one verify question".
 * The `verify` command and every element of a batch both go through it, so a
 * batch element can never differ from the same question asked alone (the
 * counterpart of Go's verifyAnswer). Isolation is by input: an element that is
 * not a valid question gets its own invalid_input. There is no per-element
 * catch. verify never throws on validated input, so a throw is a verifier bug,
 * and it reaches dispatch's last-resort catch as one internal_error for the
 * whole call, as in Go and Python. Catching it here would turn a bug into a
 * per-element answer that only TS gives.
 *
 * The stdin gate has already judged the whole text, so a text fault anywhere
 * (lone surrogate, non-finite number, nesting over the depth limit) never gets
 * here and fails the whole batch.
 */
import { validateInput } from './schema.js';
import { verify, type VerifyInput } from './verify.js';

/**
 * The most questions one call answers. A count, not a byte size, so the
 * boundary is deterministic. Going over it is batch_too_large: the caller must
 * split the batch, a different action from fixing malformed input.
 */
export const MAX_BATCH_QUESTIONS = 65536;

/** What `verify` prints for one question: a verdict, or invalid_input when it is not a valid question. */
export function verifyAnswer(question: unknown): unknown {
  if (question === null || typeof question !== 'object' || Array.isArray(question)) {
    return { error: 'invalid_input' };
  }
  if (!validateInput('verify', question as Record<string, unknown>)) {
    return { error: 'invalid_input' };
  }
  return verify(question as VerifyInput);
}

export function verifyBatch(input: { questions: readonly unknown[] }): unknown {
  if (input.questions.length > MAX_BATCH_QUESTIONS) return { error: 'batch_too_large' };
  return { results: input.questions.map(verifyAnswer) };
}
