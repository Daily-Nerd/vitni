// DESIGN.md Appendix A describes the local key registry for people who
// deploy a verifier. It is non-normative: CONTRACT.md section 7 and the
// vectors own the behavior. These tests keep it from drifting: every vector
// it cites exists, its example registry is the one a vector verifies, it adds
// at most one MUST, it restates no table that CONTRACT.md owns, and it carries
// no attribution.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const design = readFileSync(join(ROOT, "docs/DESIGN.md"), "utf8");
const HEADING = "## Appendix A. Local key registry (non-normative)";

function appendix() {
  const at = design.indexOf(HEADING);
  assert.ok(at >= 0, `DESIGN.md has the heading "${HEADING}"`);
  const rest = design.slice(at + HEADING.length);
  const next = rest.search(/^## /m);
  return HEADING + (next < 0 ? rest : rest.slice(0, next));
}

const citedVectors = (text) => [...text.matchAll(/`vectors\/([a-z0-9-]+)`/g)].map((m) => m[1]);

test("the appendix is the last section, after section 19", () => {
  const at = design.indexOf(HEADING);
  assert.ok(at > design.indexOf("## 19. Known gaps / roadmap"), "after section 19");
  assert.equal(design.slice(at + HEADING.length).search(/^## /m), -1, "no section follows it");
});

test("S3.1 every vector the appendix cites exists, and the registry-shape vectors are cited", () => {
  const cited = citedVectors(appendix());
  assert.ok(cited.length > 0, "the appendix cites vectors");
  for (const stem of cited) {
    assert.ok(existsSync(join(ROOT, "conformance/vectors", `${stem}.json`)), `vector ${stem} exists`);
  }
  for (const stem of [
    "verify-extra-members-ignored",
    "verify-key-eddsa-kty-ec",
    "verify-key-es256-kty-okp",
    "verify-key-alg-rs256",
    "verify-key-revoked-and-mismatched",
    "verify-status-odd-is-active",
    "verify-key-member-case-status",
    "verify-key-entry-null",
    "verify-key-eddsa-x-padded",
    "neg-verify-key-x-number",
  ]) {
    assert.ok(cited.includes(stem), `the appendix cites ${stem}`);
  }
});

test("the example registry is the one a vector verifies", () => {
  const text = appendix();
  const m = text.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(m, "the appendix has a json example");
  const vec = JSON.parse(readFileSync(join(ROOT, "conformance/vectors/verify-extra-members-ignored.json"), "utf8"));
  assert.deepEqual(vec.anchor, { valid: true, reason: "ok" });
  assert.deepEqual(JSON.parse(m[1]), vec.input.keys, "the example equals the vector's keys, member for member");
});

test("S3.2 the appendix adds exactly one MUST, and says so is non-normative", () => {
  const text = appendix();
  assert.equal([...text.matchAll(/\bMUST\b/g)].length, 1, "exactly one MUST");
  assert.match(text, /non-normative/i);
  assert.match(text, /CONTRACT\.md/, "points at the normative source");
});

test("the appendix reserves nothing: no profile, no reserved member names, no future promise", () => {
  const text = appendix().replace(/\s+/g, " ");
  assert.ok(!/WA-ES256/i.test(text), "no WA-ES256");
  assert.ok(!/web\s?authn|passkey/i.test(text), "no WebAuthn or passkey mention");
  assert.ok(!/reserved|deferred|later use|not part of this release/i.test(text), "no reservation or deferral wording");
});

test("S3.3 the appendix and the section 10 pointer carry no em-dash, attribution or vector count", () => {
  const pointer = design.split("\n").filter((l) => l.includes("Appendix A") && !l.startsWith("## "));
  assert.ok(pointer.length >= 1, "section 10 points at the appendix");
  const text = appendix() + "\n" + pointer.join("\n");
  assert.ok(!text.includes("\u2014"), "no em-dash");
  assert.ok(!/claude|anthropic|generated with|co-authored|session_/i.test(text), "no attribution");
  assert.ok(!/\b\d{2,3}\s+(?:[\w-]+\s+){0,3}vectors\b/.test(text), "no vector count");
});

test("W1 the appendix restates no table: CONTRACT.md owns the member list, the binding and the outcomes", () => {
  const rows = appendix().split("\n").filter((l) => /^\s*\|/.test(l));
  assert.deepEqual(rows, [], "no markdown table row in the appendix");
});

test("W1 the appendix links to the owning CONTRACT.md section and steps, and they exist", () => {
  const text = appendix().replace(/\s+/g, " ");
  assert.match(text, /`conformance\/CONTRACT\.md` section 7/);
  assert.match(text, /steps 5 and 6/);
  const contract = readFileSync(join(ROOT, "conformance/CONTRACT.md"), "utf8");
  const at = contract.indexOf("### 7. `verify`");
  assert.ok(at >= 0, "CONTRACT.md section 7 is the verify command");
  const sec = contract.slice(at, contract.indexOf("\n### 8.", at));
  assert.match(sec, /^5\. `alg_not_allowed`/m, "step 5 is the key-type binding");
  assert.match(sec, /^6\. `bad_signature`/m, "step 6 is the key material rule");
});
