// CONTRACT.md is what a third-party implementer reads. It must describe the
// harness as it is: N implementations, the real path, no stale version, and
// the profile/decline/floor rules a new implementation has to follow.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
