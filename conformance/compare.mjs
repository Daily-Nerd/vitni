#!/usr/bin/env node
// vitni conformance harness — runs every vector through BOTH reference verifiers
// (Go + TypeScript) and asserts byte-identical output + match to the external anchor.
// Agreement across two independent runtimes is the interoperability guarantee.
//
//   GO_VERIFY="./bin/vitni-verify-go" TS_VERIFY="node ts/dist/cli.js" node conformance/compare.mjs
import { readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));   // conformance/
const ROOT = join(HERE, "..");                          // repo root
const VECTORS = join(HERE, "vectors");

const GO = (process.env.GO_VERIFY ?? "./bin/vitni-verify-go").trim();
const TS = (process.env.TS_VERIFY ?? "node ts/dist/cli.js").trim();

function run(cmdStr, subcommand, inputObj) {
  const parts = cmdStr.split(/\s+/);
  const res = spawnSync(parts[0], [...parts.slice(1), subcommand], {
    cwd: ROOT, input: JSON.stringify(inputObj), encoding: "utf8",
  });
  if (res.error) return { ok: false, err: `spawn: ${res.error.message}` };
  if (res.status !== 0) return { ok: false, err: `exit ${res.status}: ${res.stderr?.slice(0, 300)}` };
  return { ok: true, out: (res.stdout ?? "").replace(/\n$/, "") };
}

function anchorMismatch(outStr, anchor) {
  let parsed;
  try { parsed = JSON.parse(outStr); } catch { return "output is not JSON"; }
  for (const [k, v] of Object.entries(anchor)) {
    if (JSON.stringify(parsed[k]) !== JSON.stringify(v)) {
      return `anchor.${k}: expected ${JSON.stringify(v)} got ${JSON.stringify(parsed[k])}`;
    }
  }
  return null;
}

const files = readdirSync(VECTORS).filter((f) => f.endsWith(".json") && !f.startsWith("_"));
let pass = 0, fail = 0;
const failures = [];

for (const f of files.sort()) {
  const vec = JSON.parse(readFileSync(join(VECTORS, f), "utf8"));
  const g = run(GO, vec.command, vec.input);
  const t = run(TS, vec.command, vec.input);
  if (!g.ok || !t.ok) { fail++; failures.push(`${vec.name}: RUNERR go=${g.err ?? "ok"} ts=${t.err ?? "ok"}`); console.log(`RUNERR  ${vec.name}`); continue; }
  if (g.out !== t.out) { fail++; failures.push(`${vec.name}: DIVERGE\n    go: ${g.out}\n    ts: ${t.out}`); console.log(`DIVERGE ${vec.name}`); continue; }
  if (vec.anchor) {
    const m = anchorMismatch(g.out, vec.anchor);
    if (m) { fail++; failures.push(`${vec.name}: ANCHOR-FAIL — ${m}\n    out: ${g.out}`); console.log(`ANCHOR  ${vec.name}`); continue; }
  }
  pass++; console.log(`PASS    ${vec.name}`);
}

console.log(`\n${pass}/${pass + fail} passed.`);
if (failures.length) { console.log("\n--- failures ---"); for (const x of failures) console.log("• " + x); process.exit(1); }
