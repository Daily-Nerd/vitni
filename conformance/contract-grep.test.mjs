// CONTRACT.md is what a third-party implementer reads. It must describe the
// harness as it is: N implementations, the real path, no stale version, and
// the profile/decline/floor rules a new implementation has to follow.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CONTRACT = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "CONTRACT.md"), "utf8");

test("CONTRACT.md carries none of the stale statements", () => {
  const stale = [
    [/harness\/compare\.mjs/, "the harness path is conformance/compare.mjs"],
    [/v0\.1/, "no stale contract version"],
    [/\bBoth\b[\s\S]{0,40}?\bGo\b\W+and\W+TypeScript/, "not 'Both Go and TypeScript': every conforming implementation"],
    [/\bBoth verifiers\b/, "not 'Both verifiers': every conforming implementation"],
    [/\*\*both\*\* binaries/, "not 'both binaries': every registered implementation"],
  ];
  for (const [re, why] of stale) assert.doesNotMatch(CONTRACT, re, why);
});

test("CONTRACT.md documents what an implementation has to do", () => {
  const required = [
    [/all conforming implementations/i, "says all conforming implementations"],
    [/conformance\/compare\.mjs/, "names the real harness path"],
    [/`profiles`/, "documents the profiles command"],
    [/profiles\.json/, "points at the catalog"],
    [/unsupported_profile/, "documents the decline"],
    [/\{"error":"unsupported_profile","profile":"<atom>"\}/, "gives the exact decline shape"],
    [/cmd:<command>/, "documents the derived command atom"],
    [/floors\.json/, "documents the floors"],
    [/"all"/, "documents the all floor"],
    [/input_raw_b64/, "documents the raw stdin form"],
    [/Empty stdin/i, "documents empty stdin"],
    [/alg_not_allowed/, "documents the key-type binding verdict"],
    [/key-type binding/i, "names the key-type binding rule"],
  ];
  for (const [re, what] of required) assert.match(CONTRACT, re, what);
});

// The Error vocabulary table is the one list of command-error codes. Every code
// a vector anchors (anchor.error) must be a row there, so the table cannot drift
// from the vectors. The reverse (every row is anchored or explicitly exempt) is
// checked by the tests further down.
test("every vector-anchored error code is in the CONTRACT.md Error vocabulary table", () => {
  const here = dirname(fileURLToPath(import.meta.url));

  const documented = new Set(errorVocabulary().keys());
  assert.ok(documented.size > 0, "the Error vocabulary table lists no codes");

  const dir = join(here, "vectors");
  const pinned = new Map(); // code -> first vector file that anchors it
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".json")).sort()) {
    const v = JSON.parse(readFileSync(join(dir, f), "utf8"));
    const code = v?.anchor?.error;
    if (typeof code === "string" && !pinned.has(code)) pinned.set(code, f);
  }
  assert.ok(pinned.size > 0, "found no vector anchor.error codes; the scan is vacuous");

  const missing = [...pinned].filter(([code]) => !documented.has(code));
  assert.deepEqual(
    missing.map(([code, f]) => `${code} (e.g. vectors/${f})`),
    [],
    "vector error codes missing from the CONTRACT.md Error vocabulary table",
  );
});

// The other direction. A table row that no vector anchors is a code two
// implementations were never compared on (receipt_id_must_be_absent was one for
// a long time). Every row must be anchored by a vector's anchor.error, or be in
// this short set of codes that no stdin bytes can produce. The set lives here,
// not in the table's "Pinned by" prose: prose cannot be parsed reliably and a
// reason is only worth anything if a test can reject it when it goes stale.
const UNREACHABLE_FROM_STDIN = new Map([
  ["missing_command", "no command argument at all; there is no stdin to put a vector's bytes in"],
  ["unsupported_profile", "a verifier's decline of a vector it does not cover; the harness checks it, no anchor can name it"],
  ["internal_error", "a verifier bug, unreachable from any stdin bytes by contract"],
  ["jcs_output_error", "a verifier bug, unreachable from any stdin bytes by contract"],
]);

// The table rows of a "## <title>" section of CONTRACT.md, as arrays of the
// raw `|`-split cells (index 0 is the empty text before the first pipe). Fails
// loudly when the section is missing; the header and separator rows are
// included and are skipped by the callers' code patterns.
function tableRows(title) {
  const section = CONTRACT.split(/^## /m).find((s) => s.startsWith(title));
  assert.ok(section, `CONTRACT.md has no '## ${title}' section`);
  return section.split("\n").filter((l) => l.startsWith("|")).map((l) => l.split("|"));
}

function errorVocabulary() {
  const rows = new Map(); // code -> "Pinned by" cell
  for (const cells of tableRows("Error vocabulary")) {
    for (const m of (cells[1] ?? "").matchAll(/`([a-z][a-z0-9_]*)`/g)) rows.set(m[1], (cells[4] ?? "").trim());
  }
  return rows;
}

function anchoredErrorCodes() {
  const dir = join(dirname(fileURLToPath(import.meta.url)), "vectors");
  const codes = new Set();
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".json"))) {
    const code = JSON.parse(readFileSync(join(dir, f), "utf8"))?.anchor?.error;
    if (typeof code === "string") codes.add(code);
  }
  return codes;
}

test("every Error vocabulary row is anchored by a vector or exempt as unreachable from stdin", () => {
  const rows = errorVocabulary();
  const anchored = anchoredErrorCodes();
  assert.ok(rows.size > 0 && anchored.size > 0, "the scan is vacuous");

  const unpinned = [...rows.keys()].filter((c) => !anchored.has(c) && !UNREACHABLE_FROM_STDIN.has(c));
  assert.deepEqual(unpinned, [], "table rows that no vector anchors and that are not exempt");
});

test("the unreachable-from-stdin exemptions are real rows and no vector anchors them", () => {
  const rows = errorVocabulary();
  const anchored = anchoredErrorCodes();
  const notRows = [...UNREACHABLE_FROM_STDIN.keys()].filter((c) => !rows.has(c));
  assert.deepEqual(notRows, [], "exempt codes that are not rows of the table (stale exemption)");
  const nowAnchored = [...UNREACHABLE_FROM_STDIN.keys()].filter((c) => anchored.has(c));
  assert.deepEqual(nowAnchored, [], "exempt codes that a vector now anchors (drop the exemption)");
});

test("a row that claims no vector pins it is exempt", () => {
  const stale = [...errorVocabulary()]
    .filter(([c, pinned]) => /\bno vector\b/i.test(pinned) && !UNREACHABLE_FROM_STDIN.has(c))
    .map(([c]) => c);
  assert.deepEqual(stale, [], "rows whose 'Pinned by' cell says no vector but are not exempt");
});

// Verdict reasons. `verify` and `verify-chain` print {"valid":..,"reason":..};
// the "Verdict reasons" table is the one list of those codes, keyed by command.
// Same two-way shape as the error gate: every vector's anchor.reason must be a
// row, and every row must be anchored by a vector or exempt below.
const UNREACHABLE_VERDICTS = new Map([
  ["verify-chain/cycle", "steps 4 and 5 fire first on any repeated receipt id; reaching it needs a SHA-256 collision or a payload that contains its own digest"],
]);

function verdictReasons() {
  const rows = new Set(); // "command/code"
  for (const cells of tableRows("Verdict reasons")) {
    const command = (cells[1] ?? "").trim().match(/^`([a-z][a-z0-9-]*)`$/)?.[1];
    const code = (cells[2] ?? "").trim().match(/^`([a-z][a-z0-9_]*)`$/)?.[1];
    if (command && code) rows.add(`${command}/${code}`);
  }
  return rows;
}

function anchoredVerdicts() {
  const dir = join(dirname(fileURLToPath(import.meta.url)), "vectors");
  const pinned = new Map(); // "command/code" -> first vector file that anchors it
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".json")).sort()) {
    const v = JSON.parse(readFileSync(join(dir, f), "utf8"));
    if (typeof v?.anchor?.reason !== "string") continue;
    const key = `${v.command}/${v.anchor.reason}`;
    if (!pinned.has(key)) pinned.set(key, f);
  }
  return pinned;
}

test("every vector-anchored verdict reason is a row of the Verdict reasons table", () => {
  const rows = verdictReasons();
  const pinned = anchoredVerdicts();
  assert.ok(rows.size > 0, "the Verdict reasons table lists no rows; the scan is vacuous");
  assert.ok(pinned.size > 0, "found no vector anchor.reason codes; the scan is vacuous");
  const missing = [...pinned].filter(([k]) => !rows.has(k));
  assert.deepEqual(
    missing.map(([k, f]) => `${k} (e.g. vectors/${f})`),
    [],
    "vector verdict reasons missing from the CONTRACT.md Verdict reasons table",
  );
});

test("every Verdict reasons row is anchored by a vector or exempt as unreachable", () => {
  const rows = verdictReasons();
  const pinned = anchoredVerdicts();
  assert.ok(rows.size > 0 && pinned.size > 0, "the scan is vacuous");
  const unpinned = [...rows].filter((k) => !pinned.has(k) && !UNREACHABLE_VERDICTS.has(k));
  assert.deepEqual(unpinned, [], "table rows that no vector anchors and that are not exempt");
});

test("the unreachable-verdict exemptions are real rows and no vector anchors them", () => {
  const rows = verdictReasons();
  const pinned = anchoredVerdicts();
  const notRows = [...UNREACHABLE_VERDICTS.keys()].filter((k) => !rows.has(k));
  assert.deepEqual(notRows, [], "exempt reasons that are not rows of the table (stale exemption)");
  const nowAnchored = [...UNREACHABLE_VERDICTS.keys()].filter((k) => pinned.has(k));
  assert.deepEqual(nowAnchored, [], "exempt reasons that a vector now anchors (drop the exemption)");
});
