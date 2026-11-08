// Guards on .github/workflows/conformance.yml: the gates that keep the vector
// set honest must exist and must be able to fail the job.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = readFileSync(join(ROOT, ".github", "workflows", "conformance.yml"), "utf8");
const CONTRIBUTING = readFileSync(join(ROOT, "CONTRIBUTING.md"), "utf8");

test("the workflow runs the harness self-tests and the tagger tests", () => {
  assert.match(WORKFLOW, /node --test conformance\/\*\.test\.mjs/);
  assert.match(WORKFLOW, /test_profiles\.py/);
});

test("the workflow regenerates every vector from nothing and requires a clean tree", () => {
  assert.match(WORKFLOW, /uses: astral-sh\/setup-uv@/);
  assert.match(WORKFLOW, /rm -f conformance\/vectors\/\*\.json/);
  for (const g of ["_gen.py", "_gen_a2a.py", "_gen_verify.py", "_gen_chain.py"]) {
    assert.ok(WORKFLOW.includes(g), `${g} is not run by the regeneration gate`);
  }
  assert.match(WORKFLOW, /git status --porcelain conformance\/vectors/);
});

test("no gate can be made non-fatal", () => {
  assert.doesNotMatch(WORKFLOW, /continue-on-error/);
});

test("the generator dependency pins live in CONTRIBUTING.md and the workflow copies them", () => {
  const pins = (text) => new Set([...text.matchAll(/--with (cryptography|ecdsa)==([0-9][0-9.]*)/g)]
    .map((m) => `${m[1]}==${m[2]}`));
  const owner = pins(CONTRIBUTING);
  assert.equal(owner.size, 2, "exactly one pin per generator dependency (cryptography, ecdsa) in CONTRIBUTING.md");
  assert.deepEqual([...pins(WORKFLOW)].sort(), [...owner].sort(), "the workflow pins differ from CONTRIBUTING.md");
});
