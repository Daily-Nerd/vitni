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
// from the vectors. The reverse is deliberately not checked: some codes are
// legitimately unpinned (missing_command, stdin_read_error).
test("every vector-anchored error code is in the CONTRACT.md Error vocabulary table", () => {
  const here = dirname(fileURLToPath(import.meta.url));

  const section = CONTRACT.split(/^## /m).find((s) => s.startsWith("Error vocabulary"));
  assert.ok(section, "CONTRACT.md has no '## Error vocabulary' section");
  const documented = new Set();
  for (const line of section.split("\n")) {
    if (!line.startsWith("|")) continue;
    const firstCell = line.split("|")[1] ?? "";
    for (const m of firstCell.matchAll(/`([a-z][a-z0-9_]*)`/g)) documented.add(m[1]);
  }
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
