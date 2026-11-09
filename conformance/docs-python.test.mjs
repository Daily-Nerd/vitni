// The docs describe the repository as it is: two full reference implementations
// plus a verify-only Python verifier, the command that tests it, and what a
// project that vendors the single file must do.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (f) => readFileSync(join(ROOT, f), "utf8");

test("the overview docs state the three verifiers accurately", () => {
  for (const f of ["AGENTS.md", "CONTRIBUTING.md", "conformance/README.md"]) {
    const text = read(f).replace(/\s+/g, " ");
    assert.match(text, /two (independent )?(full )?reference implementations/i, `${f}: the two full implementations`);
    assert.match(text, /verify-only Python verifier/, `${f}: the verify-only Python verifier`);
  }
  assert.match(read("README.md").replace(/\s+/g, " "), /Python verifier/, "README.md mentions the Python verifier");
});

test("CONTRIBUTING.md gives the Python test commands for both supported versions", () => {
  const text = read("CONTRIBUTING.md");
  for (const v of ["3.10", "3.13"]) {
    assert.ok(text.includes(`uv run --no-project --python ${v} python -I -m unittest discover -s py/tests -t py`), v);
  }
  assert.match(text, /PY_VERIFY=/, "the compare command with the Python verifier");
  assert.match(text, /py\/tests_cross/, "the second-oracle target");
});

test("CONTRIBUTING.md says how a project vendors the single file", () => {
  const text = read("CONTRIBUTING.md").replace(/\s+/g, " ");
  const required = [
    [/release tag, never `main`/, "fetch at a release tag, never main"],
    [/sha256/, "pin the sha256"],
    [/eol=lf/, "LF line endings on the vendored copy"],
    [/`\{"valid":true\}` is verified/, "valid true is verified"],
    [/`\{"valid":false\}` is failed/, "valid false is failed"],
    [/any `\{"error":\.\.\.\}` is unable/, "any error object is unable"],
    [/ES256 is raw R\|\|S/, "ES256 is R||S only"],
    [/unsupported_profile/, "declined commands"],
  ];
  for (const [re, what] of required) assert.match(text, re, what);
});

test("W2 the docs name REQUIRE_IMPLS as the one way to require an implementation, and a Go and TS run still works", () => {
  for (const f of ["CONTRIBUTING.md", "conformance/README.md"]) {
    assert.match(read(f), /REQUIRE_IMPLS/, `${f} documents REQUIRE_IMPLS`);
  }
  const contributing = read("CONTRIBUTING.md").replace(/\s+/g, " ");
  assert.doesNotMatch(contributing, /a run without `PY_VERIFY` fails/, "a run without PY_VERIFY is not a failure by itself");
  assert.match(contributing, /REQUIRE_IMPLS=go,ts,py/, "CI's required list is shown");
});
