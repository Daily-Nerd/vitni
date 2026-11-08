// Guards on the Python steps of .github/workflows/conformance.yml: the verifier
// is tested on both supported Pythons, its tests need nothing but the stdlib,
// the three-implementation compare runs per version and names all three, and no
// Python step can be made non-fatal. Text-level on purpose: the workflow is
// small and these are the properties that must survive an edit.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = readFileSync(join(ROOT, ".github", "workflows", "conformance.yml"), "utf8");
const CONTRIBUTING = readFileSync(join(ROOT, "CONTRIBUTING.md"), "utf8");

// One entry per `- name:` / `- uses:` step of the job.
const STEPS = WORKFLOW.split(/\n(?=      - )/).slice(1);
const step = (re) => {
  const found = STEPS.filter((s) => re.test(s));
  assert.equal(found.length, 1, `expected exactly one step matching ${re}, found ${found.length}`);
  return found[0];
};
const index = (s) => STEPS.indexOf(s);

test("S2.51 the Python unit tests run on 3.10 and 3.13 with no --with (stdlib only)", () => {
  const unit = step(/unittest discover -s py\/tests -t py/);
  assert.match(unit, /for v in 3\.10 3\.13; do/);
  assert.match(unit, /uv run --no-project --python "\$v" python -I -m unittest discover -s py\/tests -t py/);
  assert.doesNotMatch(unit, /--with/);
});

test("the unit tests run before the compare, uv is installed (pinned) before both", () => {
  const uv = step(/uses: astral-sh\/setup-uv@/);
  assert.match(uv, /version: "[0-9.]+"/);
  const unit = step(/unittest discover -s py\/tests -t py/);
  const compare = step(/PY_VERIFY=/);
  assert.ok(index(uv) < index(unit) && index(unit) < index(compare));
});

test("the compare runs per Python version with PY_VERIFY and requires all three impls through REQUIRE_IMPLS", () => {
  const compare = step(/PY_VERIFY=/);
  assert.match(compare, /for v in 3\.10 3\.13; do/);
  assert.match(compare, /PY_VERIFY="uv run --no-project --python \$v python -I py\/vitni_verify\.py"/);
  assert.match(compare, /REQUIRE_IMPLS=go,ts,py/);
  assert.match(compare, /node conformance\/compare\.mjs/);
  // one mechanism: the harness owns "which impls must run", no second grep of its output
  assert.doesNotMatch(compare, /grep/);
  // the old two-impl compare step is gone: no compare without PY_VERIFY
  assert.doesNotMatch(WORKFLOW, /^\s*run: node conformance\/compare\.mjs\s*$/m);
});

test("the cross-check target runs separately, with the pinned cryptography", () => {
  const cross = step(/py\/tests_cross/);
  const pin = CONTRIBUTING.match(/--with (cryptography==[0-9][0-9.]*)/);
  assert.ok(pin, "CONTRIBUTING.md owns the cryptography pin");
  assert.ok(cross.includes(`--with ${pin[1]}`), "the cross-check uses the pin owned by CONTRIBUTING.md");
  assert.doesNotMatch(step(/unittest discover -s py\/tests -t py/), /py\/tests_cross/);
});

test("S2.52 the stdlib-only grep gate fails the job when a third-party crypto name appears", () => {
  const gate = step(/cryptography\|ecdsa\|nacl/);
  assert.match(gate, /py\/vitni_verify\.py/);
  assert.match(gate, /if grep -nE 'cryptography\|ecdsa\|nacl' py\/vitni_verify\.py; then[\s\S]*exit 1/);
});

test("the workflow requires node for the number differential", () => {
  assert.match(WORKFLOW, /VITNI_REQUIRE_NODE: "1"/);
});

test("S2.58 no step, Python or otherwise, can be made non-fatal", () => {
  assert.doesNotMatch(WORKFLOW, /continue-on-error/);
  assert.doesNotMatch(WORKFLOW, /\|\|\s*true/);
});

test("the harness self-tests run after uv is installed (the live tests spawn the Python verifier)", () => {
  assert.ok(index(step(/node --test conformance\/\*\.test\.mjs/)) > index(step(/uses: astral-sh\/setup-uv@/)));
});

// A pipeline takes the exit status of its LAST command unless pipefail is set, so
// `node conformance/compare.mjs | tee log` is green whatever the harness said. GitHub's
// default `run` shell is `bash -e {0}` (no pipefail); `shell: bash` adds it.
function unguardedHarnessPipes(steps) {
  const bad = [];
  for (const s of steps) {
    const flat = s.replace(/\\\n\s*/g, " ");
    const pipes = flat.split("\n").some((l) =>
      (/compare\.mjs.*(?<!\|)\|(?!\|)/.test(l)) || /(?<!\|)\|\s*tee\b/.test(l));
    const guarded = /set -[a-z]*o pipefail|set -o pipefail/.test(flat) || /^\s*shell:\s*bash\s*$/m.test(flat);
    if (pipes && !guarded) bad.push(s.split("\n")[0].trim());
  }
  return bad;
}

test("C1 no step pipes the harness (or tee) without pipefail, so a failing harness fails the step", () => {
  assert.deepEqual(unguardedHarnessPipes(STEPS), []);
});

test("C1 the pipe check flags the unguarded shape and accepts the guarded ones", () => {
  const unguarded = "      - name: x\n        run: |\n          node conformance/compare.mjs | tee log\n          grep -q ok log\n";
  assert.deepEqual(unguardedHarnessPipes([unguarded]), ["- name: x"]);
  const continued = "      - name: y\n        run: |\n          node conformance/compare.mjs \\\n            | tee log\n";
  assert.deepEqual(unguardedHarnessPipes([continued]), ["- name: y"]);
  const teeAlone = "      - name: z\n        run: |\n          make | tee out\n";
  assert.deepEqual(unguardedHarnessPipes([teeAlone]), ["- name: z"]);
  assert.deepEqual(unguardedHarnessPipes([unguarded.replace("run: |\n", "run: |\n          set -o pipefail\n")]), []);
  assert.deepEqual(unguardedHarnessPipes([unguarded.replace("run: |", "shell: bash\n        run: |")]), []);
  // an escaped pipe inside a grep pattern and `||` are not pipelines
  const alt = "      - name: g\n        run: |\n          grep -nE 'a\\|b' f\n          node conformance/compare.mjs || exit 1\n";
  assert.deepEqual(unguardedHarnessPipes([alt]), []);
});
