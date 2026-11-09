// vitni conformance harness: runs every vector through every registered verifier
// and asserts, per vector, that each impl either ANSWERS (byte-identical to the
// other answering impls and matching the external anchor) or DECLINES with
// exactly {"error":"unsupported_profile","profile":"<atom>"}. A silent answer, a
// silent skip and a coverage drop are all failures. Pure and dependency-free:
// compare.mjs is the CLI shell, harness.test.mjs drives it with fake impls.
//
// The single sources of truth it consumes:
//   profiles.json  the catalog of profile atoms (conformance/profiles.json)
//   floors.json    per-impl lower bound on answered vectors ("all" or an integer),
//                  checked for the impls that ran
//   REQUIRE_IMPLS  the impls that must have run (see requiredImpls)
//   the vectors    each carries its own `profiles` (written by _profiles.py)
// and the single thing it owns: the vector count (`vectors: N` in its output).
import { readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url)); // conformance/
export const ROOT = join(HERE, "..");                 // repo root
export const DEFAULT_VECTORS = join(HERE, "vectors");
export const DEFAULT_CATALOG = join(HERE, "profiles.json");
export const DEFAULT_FLOORS = join(HERE, "floors.json");

const ATOM_ID = /^[a-z0-9]+:[A-Za-z0-9._-]+$/;
const INPUT_FORMS = ["input", "input_raw", "input_raw_b64"];

// The registry. Order is the report column order. go and ts always run; py runs
// only when PY_VERIFY is set. Which impls MUST have run is not decided here: it
// is the one list in REQUIRE_IMPLS (requiredImpls), which CI sets to go,ts,py.
export function defaultImpls(env = process.env) {
  const split = (s) => s.trim().split(/\s+/);
  const impls = [
    { name: "go", argv: split(env.GO_VERIFY ?? "./bin/vitni-verify-go"), env: {} },
    { name: "ts", argv: split(env.TS_VERIFY ?? "node ts/dist/cli.js"), env: {} },
  ];
  if (env.PY_VERIFY !== undefined && env.PY_VERIFY.trim() !== "") {
    impls.push({ name: "py", argv: split(env.PY_VERIFY), env: {} });
  }
  return impls;
}

// REQUIRE_IMPLS is a comma separated list of impl names that must be part of the
// run (empty or unset: no requirement). An impl on the list that did not run is
// IMPL-MISSING, so dropping one from a CI run is a failure, not a smaller run.
export function requiredImpls(env = process.env) {
  return (env.REQUIRE_IMPLS ?? "").split(",").map((n) => n.trim()).filter((n) => n !== "");
}

export function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

// stdinBytes is the exact byte string written to the verifier's stdin. A vector
// pins it in exactly one of three forms:
//   input          structured JSON, serialized here
//   input_raw      the exact stdin text (duplicate keys, which a round-trip would collapse)
//   input_raw_b64  standard base64 of the exact stdin BYTES (invalid UTF-8, BOM)
// A present-but-empty value is EMPTY stdin, never "absent": presence is tested
// with `!== undefined`, not truthiness.
export function stdinBytes(vec) {
  const forms = INPUT_FORMS.filter((k) => vec[k] !== undefined);
  if (forms.length !== 1) {
    throw new Error(`exactly one of ${INPUT_FORMS.join(", ")} required, found [${forms.join(", ")}]`);
  }
  if (vec.input_raw_b64 !== undefined) return Buffer.from(vec.input_raw_b64, "base64");
  if (vec.input_raw !== undefined) return Buffer.from(vec.input_raw, "utf8");
  return Buffer.from(JSON.stringify(vec.input), "utf8");
}

const oneLine = (s) => String(s).replace(/\s+/g, " ").trim();

// stdout is captured as raw bytes and compared as bytes: decoding as UTF-8
// first would turn an invalid byte (a raw 0xff echoed back by an impl) into
// U+FFFD and hide the bug. Output that is not strict UTF-8 fails the vector.
function spawnImpl(impl, subcommand, stdin, cwd) {
  const [cmd, ...args] = impl.argv;
  const res = spawnSync(cmd, [...args, subcommand], {
    cwd, input: stdin, env: { ...process.env, ...(impl.env ?? {}) },
  });
  if (res.error) return { ok: false, spawn: true, err: `spawn: ${res.error.message}` };
  if (res.status !== 0) {
    return { ok: false, err: `exit ${res.status}: ${oneLine((res.stderr ?? "").toString("utf8").slice(0, 200))}` };
  }
  let out = res.stdout ?? Buffer.alloc(0);
  if (out.length > 0 && out[out.length - 1] === 0x0a) out = out.subarray(0, out.length - 1);
  try {
    new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(out);
  } catch {
    return { ok: false, nonUtf8: true, outBuf: out };
  }
  return { ok: true, outBuf: out, out: out.toString("utf8") };
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { return undefined; }
}

// An output that is an {"error": ...} object requires an anchor asserting the
// expected error code. Without it, "both implementations errored identically"
// is indistinguishable from "both are correctly succeeding": a bug where both
// wrongly reject would still count as agreement.
function isErrorOutput(text) {
  const p = parseJson(text);
  return p !== null && typeof p === "object" && !Array.isArray(p) && "error" in p;
}

function anchorMismatch(text, anchor) {
  const parsed = parseJson(text);
  if (parsed === undefined || parsed === null || typeof parsed !== "object") return "output is not a JSON object";
  for (const [k, v] of Object.entries(anchor)) {
    if (JSON.stringify(parsed[k]) !== JSON.stringify(v)) {
      return `anchor.${k}: expected ${JSON.stringify(v)} got ${JSON.stringify(parsed[k])}`;
    }
  }
  return null;
}

// Catalog shape. The catalog is the one list of atoms; cmd:* atoms are derived
// from the vector's `command` and never listed.
export function validateCatalog(catalog) {
  const failures = [];
  const seen = new Set();
  if (catalog === null || typeof catalog !== "object" || !Array.isArray(catalog.atoms)) {
    return ["BADCATALOG catalog: an object with an `atoms` array is required"];
  }
  for (const a of catalog.atoms) {
    const id = a?.id;
    if (typeof id !== "string") { failures.push("BADCATALOG <no id>: every atom needs a string id"); continue; }
    if (!ATOM_ID.test(id)) failures.push(`BADCATALOG ${id}: id does not match ${ATOM_ID}`);
    if (id.startsWith("cmd:")) failures.push(`BADCATALOG ${id}: cmd:* atoms are derived from the command, never catalogued`);
    if (seen.has(id)) failures.push(`BADCATALOG ${id}: duplicate id`);
    seen.add(id);
    if (typeof a.gating !== "boolean") failures.push(`BADCATALOG ${id}: gating must be a boolean`);
    for (const f of ["section", "status"]) {
      if (typeof a[f] !== "string") failures.push(`BADCATALOG ${id}: ${f} must be a string`);
    }
  }
  return failures;
}

function validateFloors(floors, ran) {
  const failures = [];
  if (floors === null || typeof floors !== "object" || Array.isArray(floors)) {
    return ["BADFLOOR floors: an object of impl name to \"all\" or a non-negative integer is required"];
  }
  for (const [name, v] of Object.entries(floors)) {
    if (v !== "all" && !(Number.isInteger(v) && v >= 0)) {
      failures.push(`BADFLOOR ${name}: ${JSON.stringify(v)} is not "all" or a non-negative integer`);
    }
  }
  for (const name of ran) {
    if (!(name in floors)) failures.push(`FLOOR-KEYS ${name}: no floor entry for an impl that ran`);
  }
  return failures;
}

function loadVectors(vectorsDir, catalogIds, failures) {
  const files = readdirSync(vectorsDir).filter((f) => f.endsWith(".json") && !f.startsWith("_")).sort();
  const vectors = [];
  for (const f of files) {
    const base = f.slice(0, -".json".length);
    let vec;
    try { vec = loadJson(join(vectorsDir, f)); } catch (e) {
      failures.push(`BADVEC ${base}: not JSON (${oneLine(e.message)})`);
      vectors.push({ file: base, bad: true });
      continue;
    }
    const entry = { file: base, name: vec.name ?? base, vec, bad: false };
    vectors.push(entry);
    const bad = (line) => { failures.push(line); entry.bad = true; };
    try { entry.stdin = stdinBytes(vec); } catch (e) { bad(`BADVEC ${entry.name}: ${e.message}`); }
    if (typeof vec.command !== "string") bad(`BADVEC ${entry.name}: no command`);
    if (!Array.isArray(vec.profiles)) {
      bad(`UNTAGGED ${entry.name}: no profiles member (generate vectors through _profiles.py)`);
      continue;
    }
    for (const atom of vec.profiles) {
      if (typeof atom !== "string") bad(`UNKNOWN-ATOM ${entry.name}: profiles entry ${JSON.stringify(atom)} is not a string`);
      else if (atom.startsWith("cmd:")) bad(`CMD-ATOM-STORED ${entry.name}: ${atom} is derived from the command and must not be stored`);
      else if (!catalogIds.has(atom)) bad(`UNKNOWN-ATOM ${entry.name}: atom ${atom} is not in the catalog`);
    }
  }
  return vectors;
}

// Read one impl's declaration. Returns { declared: Set } or { hard: line }.
function readDeclaration(impl, cwd, catalogById, failures) {
  const r = spawnImpl(impl, "profiles", Buffer.alloc(0), cwd);
  if (!r.ok) {
    return { hard: r.spawn
      ? `IMPL-UNSPAWNABLE ${impl.name}: ${r.err}`
      : `DECL-INVALID ${impl.name}: profiles ${r.nonUtf8 ? "printed non-UTF-8" : r.err}` };
  }
  const list = parseJson(r.out);
  if (!Array.isArray(list) || list.some((x) => typeof x !== "string")) {
    return { hard: `DECL-INVALID ${impl.name}: profiles must print a JSON array of strings, got ${oneLine(r.out).slice(0, 120)}` };
  }
  if (r.out !== JSON.stringify(list) || list.join("\u0000") !== [...list].sort().join("\u0000")
      || new Set(list).size !== list.length) {
    failures.push(`DECL-INVALID ${impl.name}: profiles must be compact, sorted by code point and unique`);
  }
  for (const atom of list) {
    const def = catalogById.get(atom);
    if (def === undefined) failures.push(`DECL-UNKNOWN ${impl.name}: declares ${atom}, which is not in the catalog`);
    else if (!def.gating) failures.push(`DECL-NONGATING ${impl.name}: declares ${atom}, a non-gating atom (declarations carry gating atoms only)`);
  }
  return { declared: new Set(list) };
}

export function runSuite({ impls, vectorsDir = DEFAULT_VECTORS, catalog, floors, required = [], cwd = ROOT }) {
  const failures = [...validateCatalog(catalog)];
  const names = impls.map((i) => i.name);
  for (const name of required) {
    if (!names.includes(name)) failures.push(`IMPL-MISSING ${name}: required by REQUIRE_IMPLS but did not run (set its *_VERIFY variable)`);
  }
  const catalogAtoms = Array.isArray(catalog?.atoms) ? catalog.atoms.filter((a) => typeof a?.id === "string") : [];
  const catalogById = new Map(catalogAtoms.map((a) => [a.id, a]));
  const catalogIds = new Set(catalogById.keys());
  const gatingIds = new Set(catalogAtoms.filter((a) => a.gating === true).map((a) => a.id));

  const vectors = loadVectors(vectorsDir, catalogIds, failures);
  const total = vectors.length;
  const base = { impls: names, total, matrix: [], failures, failedVectors: new Set(vectors.filter((v) => v.bad).map((v) => v.name ?? v.file)) };
  const finish = () => ({ ...base, passed: total - base.failedVectors.size, ok: failures.length === 0 });

  // Each impl declares its gating atoms, once, with empty stdin.
  const declared = new Map();
  let hard = false;
  for (const impl of impls) {
    const d = readDeclaration(impl, cwd, catalogById, failures);
    if (d.hard) { failures.push(d.hard); hard = true; } else declared.set(impl.name, d.declared);
  }
  if (hard) return finish();   // cannot judge coverage with an impl that does not run

  // Dead gating atom (S1.4): a catalog atom nothing exercises.
  const used = new Set(vectors.filter((v) => !v.bad).flatMap((v) => v.vec.profiles));
  for (const id of gatingIds) {
    if (!used.has(id)) failures.push(`DEAD-ATOM ${id}: gating atom has no vector`);
  }

  const answered = Object.fromEntries(names.map((n) => [n, 0]));
  const answeredAtoms = Object.fromEntries(names.map((n) => [n, new Set()]));
  const cmdDeclines = Object.fromEntries(names.map((n) => [n, new Map()]));   // command -> count
  const cmdTotals = new Map();                                                // command -> vectors
  const groups = new Map();                                                   // prefix -> {total, answered:{impl:n}}

  for (const entry of vectors) {
    if (entry.bad) continue;
    const { vec, name } = entry;
    const failAt = (line) => { failures.push(line); base.failedVectors.add(name); };
    const gating = vec.profiles.filter((a) => gatingIds.has(a));
    cmdTotals.set(vec.command, (cmdTotals.get(vec.command) ?? 0) + 1);
    const group = entry.file.split("-")[0];
    if (!groups.has(group)) groups.set(group, { total: 0, answered: Object.fromEntries(names.map((n) => [n, 0])) });
    groups.get(group).total++;

    const runs = impls.map((impl) => ({ impl, r: spawnImpl(impl, vec.command, entry.stdin, cwd) }));
    const bad = runs.filter(({ r }) => !r.ok);
    if (bad.length > 0) {
      const nonUtf8 = runs.some(({ r }) => r.nonUtf8);
      const detail = runs.map(({ impl, r }) => `${impl.name}=${r.nonUtf8 ? r.outBuf.toString("hex") : r.ok ? "ok" : r.err}`).join(" ");
      failAt(`${nonUtf8 ? "NON-UTF8-OUTPUT" : "RUNERR"} ${name}: ${detail}`);
      continue;
    }

    const answers = [];
    let vectorFailed = false;
    for (const { impl, r } of runs) {
      const missing = gating.filter((a) => !declared.get(impl.name).has(a));
      const allowed = new Set([...missing, `cmd:${vec.command}`]);
      if (r.outBuf.length === 0) {
        failAt(`EMPTY-OUTPUT ${name} ${impl.name}: nothing on stdout (a silent skip is never a pass)`);
        vectorFailed = true;
        continue;
      }
      const parsed = parseJson(r.out);
      const isDecline = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
        && parsed.error === "unsupported_profile";
      if (!isDecline) {
        if (missing.length > 0) {
          failAt(`SILENT-ANSWER ${name} ${impl.name}: answered but does not declare ${missing.join(", ")}; expected unsupported_profile`);
          vectorFailed = true;
          continue;
        }
        answers.push({ impl, r });
        continue;
      }
      // A decline: exact bytes, and the profile must be one the impl may name.
      const p = parsed.profile;
      if (typeof p !== "string") {
        failAt(`BADDECLINE ${name} ${impl.name}: unsupported_profile needs a string \`profile\` member`);
        vectorFailed = true;
        continue;
      }
      if (r.out !== JSON.stringify({ error: "unsupported_profile", profile: p })) {
        failAt(`BADDECLINE ${name} ${impl.name}: not exactly {"error":"unsupported_profile","profile":"<atom>"}: ${oneLine(r.out).slice(0, 120)}`);
        vectorFailed = true;
        continue;
      }
      if (!allowed.has(p)) {
        failAt(`BADDECLINE ${name} ${impl.name}: profile ${p} is not a missing atom (${[...allowed].join(", ")} allowed)`);
        vectorFailed = true;
        continue;
      }
      if (vec.anchor && (vec.anchor.error === "unsupported_command" || vec.anchor.error === "missing_command")) {
        failAt(`CONFLATED ${name} ${impl.name}: ${vec.anchor.error} is a CLI error every impl answers, never unsupported_profile`);
        vectorFailed = true;
        continue;
      }
      if (p === `cmd:${vec.command}`) {
        const m = cmdDeclines[impl.name];
        m.set(vec.command, (m.get(vec.command) ?? 0) + 1);
      }
    }
    if (vectorFailed && answers.length === 0) continue;

    for (const { impl } of answers) {
      answered[impl.name]++;
      groups.get(group).answered[impl.name]++;
      for (const a of gating) answeredAtoms[impl.name].add(a);
    }

    if (answers.length === 0) {
      if (!vectorFailed) failAt(`ORPHAN ${name}: no impl answered it (every impl is out of scope)`);
      continue;
    }
    const first = answers[0];
    for (const other of answers.slice(1)) {
      if (!other.r.outBuf.equals(first.r.outBuf)) {
        failAt(`DIVERGE ${name} ${first.impl.name} vs ${other.impl.name}: ${first.impl.name}=${first.r.out} ${other.impl.name}=${other.r.out}`);
        vectorFailed = true;
      }
    }
    if (vectorFailed) continue;
    if (isErrorOutput(first.r.out) && !vec.anchor) {
      failAt(`NOANCHOR ${name}: impls returned ${first.r.out} but no anchor asserts the expected error code`);
      continue;
    }
    if (!vec.anchor && answers.length < 2) {
      failAt(`UNWITNESSED ${name}: unanchored vector answered by only ${first.impl.name}; needs two impls or an anchor`);
      continue;
    }
    if (vec.anchor) {
      const m = anchorMismatch(first.r.out, vec.anchor);
      if (m) failAt(`ANCHOR-FAIL ${name}: ${m} (out: ${first.r.out})`);
    }
  }

  // Per-command decline uniformity: an impl either declines a command or answers it.
  for (const impl of impls) {
    for (const [command, n] of cmdDeclines[impl.name]) {
      const t = cmdTotals.get(command);
      if (n !== t) failures.push(`NONUNIFORM ${impl.name} ${command}: declined ${n} of ${t} vectors (a command is declined for all of them or none)`);
    }
  }

  // Dead profile (S1.17): a declared atom the impl never answered a vector for.
  for (const impl of impls) {
    for (const atom of [...declared.get(impl.name)].filter((a) => gatingIds.has(a)).sort()) {
      if (!answeredAtoms[impl.name].has(atom)) failures.push(`DEAD-PROFILE ${impl.name} ${atom}: declared but no vector with it was answered`);
    }
  }

  // Floors (S1.18, S1.23): a lower bound on answered vectors.
  failures.push(...validateFloors(floors, names));
  if (floors !== null && typeof floors === "object") {
    for (const impl of impls) {
      const floor = floors[impl.name];
      const got = answered[impl.name];
      if (floor === "all" && got < total) failures.push(`FLOOR-BREACH ${impl.name}: ${got} < all (${total})`);
      else if (Number.isInteger(floor) && got < floor) failures.push(`FLOOR-BREACH ${impl.name}: ${got} < ${floor}`);
    }
  }

  const matrix = [...groups.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([group, g]) => ({
    group, total: g.total,
    cells: Object.fromEntries(names.map((n) => [n, `${g.answered[n]}/${g.total}`])),
  }));
  base.matrix = matrix;
  base.answered = answered;
  return finish();
}

export function formatReport(res) {
  const lines = [`impls: ${res.impls.join(" ")}`];
  lines.push("", "--- coverage ---");
  const width = Math.max(5, ...res.matrix.map((r) => r.group.length));
  lines.push(`${"group".padEnd(width)}  ${res.impls.map((n) => n.padEnd(8)).join(" ")}`);
  for (const row of res.matrix) {
    lines.push(`${row.group.padEnd(width)}  ${res.impls.map((n) => row.cells[n].padEnd(8)).join(" ")}`);
  }
  if (res.failures.length > 0) {
    lines.push("", "--- failures ---");
    for (const f of res.failures) lines.push(`* ${f}`);
  }
  lines.push("", `vectors: ${res.total}`, `${res.passed}/${res.total} passed.`);
  return lines.join("\n");
}
