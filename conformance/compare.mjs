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

// stdinBytes is the exact byte string written to the verifier's stdin, as a
// Buffer. A vector pins its stdin in exactly one of three forms:
//   input          structured JSON, serialized here
//   input_raw      the exact stdin text (e.g. duplicate JSON keys, which a
//                  JSON.parse->stringify round-trip would silently collapse)
//   input_raw_b64  standard base64 of the exact stdin BYTES (invalid UTF-8, BOM,
//                  anything a JS string cannot carry)
// A present-but-empty value is EMPTY stdin, never "absent": presence is tested
// with `!== undefined`, not truthiness.
function stdinBytes(vec) {
  const forms = ["input", "input_raw", "input_raw_b64"].filter((k) => vec[k] !== undefined);
  if (forms.length !== 1) {
    throw new Error(`${vec.name}: exactly one of input, input_raw, input_raw_b64 required, found [${forms.join(", ")}]`);
  }
  if (vec.input_raw_b64 !== undefined) return Buffer.from(vec.input_raw_b64, "base64");
  if (vec.input_raw !== undefined) return Buffer.from(vec.input_raw, "utf8");
  return Buffer.from(JSON.stringify(vec.input), "utf8");
}

// stdout is captured as raw bytes and compared as bytes: decoding as UTF-8
// first would turn an invalid byte (e.g. a raw 0xff echoed back by an impl)
// into U+FFFD and hide the bug. Output that is not strict UTF-8 fails the vector.
function run(cmdStr, subcommand, stdin) {
  const parts = cmdStr.split(/\s+/);
  const res = spawnSync(parts[0], [...parts.slice(1), subcommand], {
    cwd: ROOT, input: stdin,
  });
  if (res.error) return { ok: false, err: `spawn: ${res.error.message}` };
  if (res.status !== 0) return { ok: false, err: `exit ${res.status}: ${res.stderr?.toString("utf8").slice(0, 300)}` };
  let out = res.stdout ?? Buffer.alloc(0);
  if (out.length > 0 && out[out.length - 1] === 0x0a) out = out.subarray(0, out.length - 1);
  try {
    new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(out);
  } catch {
    return { ok: false, nonUtf8: true, outBuf: out };
  }
  return { ok: true, outBuf: out, out: out.toString("utf8") };
}

// An output that is an {"error": ...} object requires an anchor asserting the
// expected error code. Without it, "both implementations errored identically"
// is indistinguishable from "both are correctly succeeding" — a bug where both
// wrongly reject would still count as agreement. Force negative vectors to
// declare their expected error.
function isErrorOutput(outStr) {
  try {
    const p = JSON.parse(outStr);
    return p !== null && typeof p === "object" && "error" in p;
  } catch {
    return false;
  }
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
  let stdin;
  try { stdin = stdinBytes(vec); } catch (e) { fail++; failures.push(e.message); console.log(`BADVEC  ${f}`); continue; }
  const g = run(GO, vec.command, stdin);
  const t = run(TS, vec.command, stdin);
  if (g.nonUtf8 || t.nonUtf8) {
    fail++; failures.push(`${vec.name}: NON-UTF8-OUTPUT go=${g.nonUtf8 ? g.outBuf.toString("hex") : "ok"} ts=${t.nonUtf8 ? t.outBuf.toString("hex") : "ok"}`); console.log(`NONUTF8 ${vec.name}`); continue;
  }
  if (!g.ok || !t.ok) { fail++; failures.push(`${vec.name}: RUNERR go=${g.err ?? "ok"} ts=${t.err ?? "ok"}`); console.log(`RUNERR  ${vec.name}`); continue; }
  if (!g.outBuf.equals(t.outBuf)) { fail++; failures.push(`${vec.name}: DIVERGE\n    go: ${g.out}\n    ts: ${t.out}`); console.log(`DIVERGE ${vec.name}`); continue; }
  if (isErrorOutput(g.out) && !vec.anchor) {
    fail++; failures.push(`${vec.name}: UNANCHORED-ERROR — both impls returned ${g.out} but no anchor asserts the expected error code`); console.log(`NOANCHOR ${vec.name}`); continue;
  }
  if (vec.anchor) {
    const m = anchorMismatch(g.out, vec.anchor);
    if (m) { fail++; failures.push(`${vec.name}: ANCHOR-FAIL — ${m}\n    out: ${g.out}`); console.log(`ANCHOR  ${vec.name}`); continue; }
  }
  pass++; console.log(`PASS    ${vec.name}`);
}

console.log(`\n${pass}/${pass + fail} passed.`);
if (failures.length) { console.log("\n--- failures ---"); for (const x of failures) console.log("• " + x); process.exit(1); }
