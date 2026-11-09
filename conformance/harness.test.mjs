// Self-tests for the conformance harness (runSuite), driven by scriptable fake
// implementations. Each test seeds ONE defect and asserts the harness names it.
//
//   node --test conformance/
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runSuite, formatReport, requiredImpls } from "./harness.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "test-fixtures", "fake-impl.mjs");
const CATALOG = JSON.parse(readFileSync(join(HERE, "test-fixtures", "catalog.json"), "utf8"));
const ALL = ["alg:ES256", "alg:EdDSA", "canon:b64-strict", "canon:jcs"];

function vec(name, command, profiles, anchor, extra = {}) {
  const v = { name, command, profiles, input: { n: name }, ...extra };
  if (anchor !== undefined) v.anchor = anchor;
  return v;
}

// Together these exercise every gating atom, so no atom is dead by accident.
const BASE = [
  vec("ed1", "verify", ["alg:EdDSA", "canon:b64-strict", "canon:jcs"], { valid: true }),
  vec("es1", "verify", ["alg:ES256", "canon:b64-strict", "canon:jcs"], { valid: true }),
  vec("j1", "jcs", ["canon:jcs"], { canonical_hex: "31" }),
  vec("d1", "digest", ["canon:b64-strict"], { digest_hex: "00" }),
];

// impl: [name, mode, {declared?, env?}]
function suite(vectors, impls, { floors, catalog = CATALOG, required } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "vitni-harness-"));
  for (const v of vectors) writeFileSync(join(dir, `${v.name}.json`), JSON.stringify(v));
  const list = impls.map(([name, mode = "echo-anchor", cfg = {}]) => ({
    name,
    argv: [process.execPath, FAKE, mode],
    env: {
      FAKE_VECTORS: dir,
      ...(cfg.declared ? { FAKE_DECLARED: JSON.stringify(cfg.declared) } : {}),
      ...(cfg.env ?? {}),
    },
  }));
  const fl = floors ?? Object.fromEntries(impls.map(([n]) => [n, "all"]));
  return { dir, ...runSuite({ impls: list, vectorsDir: dir, catalog, floors: fl, required }) };
}

function assertFails(res, re, msg) {
  assert.ok(res.failures.some((l) => re.test(l)), `${msg ?? re}: no failure line matches; got:\n${res.failures.join("\n")}`);
  assert.ok(res.failures.every((l) => !l.includes("\n")), "every failure is exactly one line");
}

const TWO = [["a"], ["b"]];

test("baseline: two honest impls over a tiny suite pass", () => {
  const r = suite(BASE, TWO);
  assert.deepEqual(r.failures, []);
  assert.equal(r.total, 4);
  assert.equal(r.passed, 4);
});

test("S1.1 an unknown atom in a vector names the vector and the atom", () => {
  const r = suite([...BASE, vec("typo", "jcs", ["alg:EdDSa"], { canonical_hex: "31" })], TWO);
  assertFails(r, /UNKNOWN-ATOM typo.*alg:EdDSa/);
});

test("S1.2 an unknown atom in a declaration names the impl and the atom", () => {
  const r = suite(BASE, [["a"], ["b", "declare-unknown"]]);
  assertFails(r, /DECL-UNKNOWN b.*alg:Nope/);
});

test("S1.3 a stored cmd: atom is rejected as derived", () => {
  const r = suite([...BASE, vec("stored", "jcs", ["canon:jcs", "cmd:jcs"], { canonical_hex: "31" })], TWO);
  assertFails(r, /CMD-ATOM-STORED stored.*cmd:jcs/);
});

test("S1.4 a gating catalog atom with no vector is a dead atom", () => {
  const r = suite(BASE.filter((v) => v.name !== "d1" && v.name !== "ed1" && v.name !== "es1"), TWO);
  assertFails(r, /DEAD-ATOM canon:b64-strict/);
  assertFails(r, /DEAD-ATOM alg:EdDSA/);
});

test("S1.6 a vector without profiles is untagged", () => {
  const bare = vec("bare", "jcs", undefined, { canonical_hex: "31" });
  delete bare.profiles;
  assertFails(suite([...BASE, bare], TWO), /UNTAGGED bare/);
});

test("a vector pinning two stdin forms, or none, is a bad vector", () => {
  const both = vec("both", "jcs", ["canon:jcs"], { canonical_hex: "31" }, { input_raw: "{}" });
  const none = vec("none", "jcs", ["canon:jcs"], { canonical_hex: "31" });
  delete none.input;
  const r = suite([...BASE, both, none], TWO);
  assertFails(r, /BADVEC both.*exactly one/);
  assertFails(r, /BADVEC none.*exactly one/);
});

test("S1.12 an out-of-scope vector answered anyway is a silent answer", () => {
  const r = suite(BASE, [["a"], ["b", "silent-answer", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: "all" } });
  assertFails(r, /SILENT-ANSWER es1 b.*alg:ES256/);
});

test("S1.13 an out-of-scope vector skipped silently fails (no output)", () => {
  const r = suite(BASE, [["a"], ["b", "silent-skip", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: 3 } });
  assertFails(r, /EMPTY-OUTPUT es1 b/);
});

test("S1.13 an impl that exits non-zero on a vector fails", () => {
  const r = suite(BASE, [["a"], ["b", "crash"]], { floors: { a: "all", b: 0 } });
  assertFails(r, /RUNERR .* b=exit 3/);
});

test("S1.14 unsupported_command may not be conflated with unsupported_profile", () => {
  const bogus = vec("bogus", "not-a-command", [], { error: "unsupported_command" });
  const ok = suite([...BASE, bogus], TWO);
  assert.deepEqual(ok.failures, []);
  const bad = suite([...BASE, bogus], [["a"], ["b", "echo-anchor", { env: { FAKE_DECLINE_CMDS: "not-a-command" } }]],
    { floors: { a: "all", b: 4 } });
  assertFails(bad, /CONFLATED bogus b/);
});

test("S1.15 an impl lacking alg:ES256 declines an ES256 vector with exactly that atom", () => {
  const r = suite(BASE, [["a"], ["b", "echo-anchor", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: 3 } });
  assert.deepEqual(r.failures, []);
  assert.equal(r.matrix.find((row) => row.group === "es1").cells.b, "0/1");
});

test("S1.15 declining with an atom that is not missing fails", () => {
  const r = suite(BASE, [["a"], ["b", "wrong-profile", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: 3 } });
  assertFails(r, /BADDECLINE es1 b.*binding:local/);
});

test("S1.16 a decline without the profile member fails", () => {
  const r = suite(BASE, [["a"], ["b", "no-profile-member", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: 3 } });
  assertFails(r, /BADDECLINE es1 b.*profile/);
});

test("S1.16 a decline with an extra member fails (exact bytes)", () => {
  const r = suite(BASE, [["a"], ["b", "extra-member", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: 3 } });
  assertFails(r, /BADDECLINE es1 b/);
});

test("an impl that declared every atom of a vector may only decline it as cmd:<command>", () => {
  const r = suite(BASE, [["a"], ["b", "echo-anchor", { env: { FAKE_FORCE_DECLINE: "alg:ES256" } }]],
    { floors: { a: "all", b: 0 } });
  assertFails(r, /BADDECLINE j1 b.*alg:ES256/);
});

test("S1.17 a declared atom the impl never answers a vector for is a dead profile", () => {
  const r = suite(BASE, [["a"], ["b", "echo-anchor", { declared: ["alg:ES256", "canon:jcs"] }]],
    { floors: { a: "all", b: 1 } });
  assertFails(r, /DEAD-PROFILE b alg:ES256/);
});

test("S1.18 an answered count below the floor is a breach and prints both numbers", () => {
  const r = suite(BASE, [["a"], ["b", "echo-anchor", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: 5 } });
  assertFails(r, /FLOOR-BREACH b.*3 < 5/);
});

test("floors are lower bounds: answering more than the floor is fine", () => {
  const r = suite(BASE, [["a"], ["b", "echo-anchor", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: 2 } });
  assert.deepEqual(r.failures, []);
});

test('"all" means answered equals total', () => {
  const r = suite(BASE, [["a"], ["b", "echo-anchor", { declared: ["alg:EdDSA", "canon:b64-strict", "canon:jcs"] }]],
    { floors: { a: "all", b: "all" } });
  assertFails(r, /FLOOR-BREACH b.*3 < all \(4\)/);
});

test("an impl that ran must have a floor entry", () => {
  assertFails(suite(BASE, TWO, { floors: { a: "all" } }), /FLOOR-KEYS .*b/);
});

test("a floor entry for an impl that did not run is not checked and not a failure", () => {
  const r = suite(BASE, TWO, { floors: { a: "all", b: "all", c: 3 } });
  assert.deepEqual(r.failures, []);
  // an entry that is malformed is still a malformed floors file, run or not
  assertFails(suite(BASE, TWO, { floors: { a: "all", b: "all", c: "most" } }), /BADFLOOR c/);
});

test("a required impl that did not run is a hard failure naming it", () => {
  assertFails(suite(BASE, TWO, { required: ["a", "b", "c"] }), /IMPL-MISSING c/);
  const none = suite(BASE, [["a"]], { required: ["a", "b"] });
  assertFails(none, /IMPL-MISSING b/);
  assert.equal(none.ok, false);
});

test("every required impl present is no failure, and no required list requires nothing", () => {
  assert.deepEqual(suite(BASE, TWO, { required: ["a", "b"] }).failures, []);
  assert.deepEqual(suite(BASE, TWO, { required: [] }).failures, []);
  assert.deepEqual(suite(BASE, TWO).failures, []);
});

test("REQUIRE_IMPLS is one comma separated list of impl names", () => {
  assert.deepEqual(requiredImpls({}), []);
  assert.deepEqual(requiredImpls({ REQUIRE_IMPLS: "" }), []);
  assert.deepEqual(requiredImpls({ REQUIRE_IMPLS: "go,ts,py" }), ["go", "ts", "py"]);
  assert.deepEqual(requiredImpls({ REQUIRE_IMPLS: " go , ts ,py," }), ["go", "ts", "py"]);
});

test("a floor must be \"all\" or a non-negative integer", () => {
  assertFails(suite(BASE, TWO, { floors: { a: "all", b: "most" } }), /BADFLOOR b/);
  assertFails(suite(BASE, TWO, { floors: { a: "all", b: -1 } }), /BADFLOOR b/);
  assertFails(suite(BASE, TWO, { floors: { a: "all", b: 1.5 } }), /BADFLOOR b/);
});

test("S1.19 a vector no impl is in scope for is an orphan", () => {
  const ed = ["alg:EdDSA", "canon:b64-strict", "canon:jcs"];
  const r = suite(BASE, [["a", "echo-anchor", { declared: ed }], ["b", "echo-anchor", { declared: ed }]],
    { floors: { a: 3, b: 3 } });
  assertFails(r, /ORPHAN es1/);
});

test("S1.20 an unspawnable impl is a hard failure, never a skip", () => {
  const dir = mkdtempSync(join(tmpdir(), "vitni-harness-"));
  writeFileSync(join(dir, "j1.json"), JSON.stringify(BASE[2]));
  const r = runSuite({
    impls: [{ name: "py", argv: ["/nonexistent/vitni-impl"], env: {} }],
    vectorsDir: dir, catalog: CATALOG, floors: { py: 0 },
  });
  assertFails(r, /IMPL-UNSPAWNABLE py/);
  assert.ok(r.failures.length > 0);
});

test("S1.21 two in-scope impls that disagree are both named, even when the first impl declined", () => {
  const r = suite(BASE, [["a"], ["b"], ["c", "different-answer"]]);
  assertFails(r, /DIVERGE j1 a vs c/);
  const first = suite(BASE, [["a", "echo-anchor", { declared: [] }], ["b"], ["c", "different-answer"]],
    { floors: { a: 0, b: "all", c: "all" } });
  assertFails(first, /DIVERGE j1 b vs c/);
});

test("S1.22 an error output without an anchor fails", () => {
  const r = suite([...BASE, vec("noanchor", "jcs", ["canon:jcs"], undefined)], TWO);
  assertFails(r, /NOANCHOR noanchor/);
});

test("an unanchored vector with a single witness is unwitnessed", () => {
  const lone = vec("lone", "jcs", ["canon:jcs"], undefined, { fake_output: { x: 1 } });
  const r = suite([...BASE, lone], [["a"], ["b", "echo-anchor", { declared: ["alg:EdDSA", "alg:ES256", "canon:b64-strict"] }]],
    { floors: { a: "all", b: 3 } });
  assertFails(r, /UNWITNESSED lone/);
});

test("an anchor mismatch is named", () => {
  const wrong = vec("wrong", "jcs", ["canon:jcs"], { canonical_hex: "31" }, { fake_output: { canonical_hex: "32" } });
  assertFails(suite([...BASE, wrong], TWO), /ANCHOR-FAIL wrong.*canonical_hex/);
});

test("output that is not strict UTF-8 is NON-UTF8-OUTPUT", () => {
  const r = suite(BASE, [["a"], ["b", "bad-utf8"]], { floors: { a: "all", b: 0 } });
  assertFails(r, /NON-UTF8-OUTPUT .*b=7bff7d/);
});

test("a declined command must be declined uniformly for every vector of that command", () => {
  const more = [...BASE, vec("j2", "jcs", ["canon:jcs"], { canonical_hex: "32" })];
  const r = suite(more, [["a"], ["b", "decline-one", { env: { FAKE_DECLINE_VECTOR: "j1" } }]],
    { floors: { a: "all", b: 3 } });
  assertFails(r, /NONUNIFORM b jcs.*1 of 2/);
});

test("declining a whole command with cmd:<command> is accepted when uniform", () => {
  const more = [...BASE, vec("j2", "jcs", ["canon:jcs"], { canonical_hex: "32" })];
  const r = suite(more, [["a"], ["b", "echo-anchor", { env: { FAKE_DECLINE_CMDS: "jcs" } }]],
    { floors: { a: "all", b: 3 } });
  assert.deepEqual(r.failures, []);
});

test("a declared non-gating atom is rejected", () => {
  assertFails(suite(BASE, [["a"], ["b", "declare-nongating"]]), /DECL-NONGATING b.*binding:mcp/);
});

test("an impl must answer or decline in scope: declaring an atom absent from profiles output", () => {
  // the harness reads the declaration from `profiles`, not from an env var it
  // controls: a fake declaring [] declines everything and is flagged as below floor
  const r = suite(BASE, [["a"], ["b", "echo-anchor", { declared: [] }]], { floors: { a: "all", b: "all" } });
  assertFails(r, /FLOOR-BREACH b/);
});

test("catalog validation: cmd: atoms, bad ids and duplicates are rejected", () => {
  const bad = { atoms: [
    { id: "cmd:jcs", section: "x", status: "stable", gating: true },
    { id: "Bad Id", section: "x", status: "stable", gating: true },
    { id: "alg:EdDSA", section: "x", status: "stable", gating: true },
    { id: "alg:EdDSA", section: "x", status: "stable", gating: true },
    { id: "canon:jcs", section: "x", status: "stable", gating: "yes" },
  ] };
  const r = suite(BASE, TWO, { catalog: bad });
  assertFails(r, /BADCATALOG cmd:jcs/);
  assertFails(r, /BADCATALOG Bad Id/);
  assertFails(r, /BADCATALOG alg:EdDSA.*duplicate/);
  assertFails(r, /BADCATALOG canon:jcs.*gating/);
});

test("S1.25 the report prints the vector count, computed from the directory", () => {
  const r = suite(BASE, TWO);
  const n = readdirSync(r.dir).filter((f) => f.endsWith(".json") && !f.startsWith("_")).length;
  const text = formatReport(r);
  assert.match(text, new RegExp(`^vectors: ${n}$`, "m"));
  assert.match(text, /^impls: a b$/m);
  assert.match(text, new RegExp(`^${n}/${n} passed\\.$`, "m"));
});

test("the report names every failure line and the matrix", () => {
  const r = suite([...BASE, vec("typo", "jcs", ["alg:EdDSa"], { canonical_hex: "31" })], TWO);
  const text = formatReport(r);
  assert.match(text, /UNKNOWN-ATOM typo/);
  assert.match(text, /--- coverage ---/);
});
