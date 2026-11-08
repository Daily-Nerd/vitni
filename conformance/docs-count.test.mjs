// The vector count has exactly one owner: the harness output (`vectors: N`).
// A number copied into a doc goes stale the next time a vector lands (it did,
// twice). This test fails on any tracked Markdown file that states one.
// CHANGELOG.md is excluded: release-please owns it and its history is dated.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// A count, up to three words, then "vectors" (may span a line break); the
// static shields badge; and the "N as of this change" idiom.
const PATTERNS = [
  /\b\d{2,3}\s+(?:[\w-]+\s+){0,3}vectors\b/g,
  /conformance-\d+/g,
  /\d+(?:\/\d+)? as of this change/g,
];

export function countSites(text) {
  const sites = [];
  for (const p of PATTERNS) {
    for (const m of text.matchAll(p)) {
      sites.push({ line: text.slice(0, m.index).split("\n").length, text: m[0].replace(/\s+/g, " ") });
    }
  }
  return sites;
}

test("the matcher catches the shapes that went stale", () => {
  const stale = [
    "all 94 vectors",
    "**bar.** 94 language-agnostic\nvectors that pin",
    "(94/94 as of this change)",
    "(all vectors must pass, 94 as of this change)",
    '<img src="https://img.shields.io/badge/conformance-94%2F94-brightgreen">',
    "a suite of 285 vectors",
  ];
  for (const s of stale) assert.ok(countSites(s).length > 0, s);
  const fine = ["the harness prints the count", "vectors: N", "all vectors pass", "2 vectors per command", "see vectors/"];
  for (const s of fine) assert.deepEqual(countSites(s), [], s);
});

test("no tracked Markdown file states the vector count", () => {
  const files = execFileSync("git", ["ls-files", "*.md"], { cwd: ROOT, encoding: "utf8" })
    .split("\n").filter((f) => f && f !== "CHANGELOG.md");
  const hits = [];
  for (const f of files) {
    for (const s of countSites(readFileSync(join(ROOT, f), "utf8"))) hits.push(`${f}:${s.line}: ${s.text}`);
  }
  assert.deepEqual(hits, [], "state no count; write \"the harness prints the count\"");
});
