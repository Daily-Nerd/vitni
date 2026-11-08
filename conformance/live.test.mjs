// Live checks against the real reference verifiers (Go and TypeScript). They
// need both built; a missing build FAILS here, it never skips:
//   mkdir -p bin && (cd go && go build -o ../bin/vitni-verify-go ./cmd/vitni-verify)
//   (cd ts && npm run build)
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { defaultImpls, DEFAULT_VECTORS, ROOT } from "./harness.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CATALOG = JSON.parse(readFileSync(join(HERE, "profiles.json"), "utf8"));
const GATING = CATALOG.atoms.filter((a) => a.gating).map((a) => a.id).sort();

function requireBuilt() {
  for (const p of ["bin/vitni-verify-go", "ts/dist/cli.js"]) {
    assert.ok(existsSync(join(ROOT, p)), `${p} is missing: build both impls first (see the header of this file)`);
  }
}

test("S1.9 Go and TS declare exactly the catalog's gating atoms, with empty stdin", () => {
  requireBuilt();
  const expected = JSON.stringify(GATING) + "\n";
  for (const impl of defaultImpls({})) {
    const [cmd, ...args] = impl.argv;
    const r = spawnSync(cmd, [...args, "profiles"], { cwd: ROOT, input: Buffer.alloc(0) });
    assert.equal(r.status, 0, impl.name);
    assert.equal(r.stdout.toString("utf8"), expected, impl.name);
  }
});

test("FX every impl answers an empty command argument unsupported_command and no argument missing_command", () => {
  requireBuilt();
  const run = (impl, extra) => {
    const [cmd, ...args] = impl.argv;
    return spawnSync(cmd, [...args, ...extra], { cwd: ROOT, input: Buffer.from("{}") }).stdout.toString("utf8");
  };
  const py = { name: "py", argv: PY_VERIFY.split(/\s+/) };
  for (const impl of [...defaultImpls({}), py]) {
    assert.equal(run(impl, [""]), '{"error":"unsupported_command"}\n', `${impl.name} empty argument`);
    assert.equal(run(impl, []), '{"error":"missing_command"}\n', `${impl.name} no argument`);
  }
});

test("S1.23 floors.json holds Go and TS at all vectors and Python at an integer lower bound", () => {
  const floors = JSON.parse(readFileSync(join(HERE, "floors.json"), "utf8"));
  assert.deepEqual(Object.keys(floors).sort(), ["go", "py", "ts"]);
  assert.equal(floors.go, "all");
  assert.equal(floors.ts, "all");
  assert.ok(Number.isInteger(floors.py) && floors.py > 0, "py floor is a positive integer taken from the harness output");
});

// The run every CI job and every contributor does: all three implementations.
const PY_VERIFY = process.env.PY_VERIFY?.trim() || "uv run --no-project python -I py/vitni_verify.py";

function rowCells(stdout) {
  const rows = stdout.split("--- coverage ---")[1].split("\n\n")[0].trim().split("\n");
  return { header: rows[0].trim().split(/\s+/).slice(1), rows: rows.slice(1).map((r) => r.trim().split(/\s+/)) };
}

test("S1.25 compare.mjs prints the three impls, the computed vector count and a clean pass", () => {
  requireBuilt();
  const r = spawnSync(process.execPath, [join(HERE, "compare.mjs")], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, PY_VERIFY },
  });
  const n = readdirSync(DEFAULT_VECTORS).filter((f) => f.endsWith(".json") && !f.startsWith("_")).length;
  assert.equal(r.status, 0, r.stdout.split("\n").filter((l) => l.startsWith("* ")).join("\n"));
  assert.match(r.stdout, /^impls: go ts py$/m);
  assert.match(r.stdout, new RegExp(`^vectors: ${n}$`, "m"));
  assert.match(r.stdout, new RegExp(`^${n}/${n} passed\\.$`, "m"));
  // Go and TS are in scope for every vector: each of their matrix cells is k/k
  const { header, rows } = rowCells(r.stdout);
  assert.deepEqual(header, ["go", "ts", "py"]);
  assert.ok(rows.length > 5);
  let py = 0;
  for (const [, go, ts, p] of rows) {
    for (const cell of [go, ts]) {
      const [a, b] = cell.split("/");
      assert.equal(a, b, `partial Go/TS scope in row: ${rows}`);
    }
    py += Number(p.split("/")[0]);
  }
  const floor = JSON.parse(readFileSync(join(HERE, "floors.json"), "utf8")).py;
  assert.ok(py >= floor, `py answered ${py} < floor ${floor}`);
});

test("S1.26 a required impl that is not run fails: dropping the Python verifier is not a smaller run", () => {
  requireBuilt();
  const r = spawnSync(process.execPath, [join(HERE, "compare.mjs")], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, PY_VERIFY: "", REQUIRE_IMPLS: "go,ts,py" },
  });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /^impls: go ts$/m);
  assert.match(r.stdout, /IMPL-MISSING py/);
  assert.doesNotMatch(r.stdout, /FLOOR-KEYS/);
});

test("S1.27 a bare run with only Go and TS passes: the Python floor applies only when Python runs", () => {
  requireBuilt();
  const r = spawnSync(process.execPath, [join(HERE, "compare.mjs")], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, PY_VERIFY: "", REQUIRE_IMPLS: "" },
  });
  assert.equal(r.status, 0, r.stdout.split("\n").filter((l) => l.startsWith("* ")).join("\n"));
  assert.match(r.stdout, /^impls: go ts$/m);
  assert.match(r.stdout, /^(\d+)\/\1 passed\.$/m);
});

test("compare.mjs exits 1 and names the failure when an impl cannot be spawned", () => {
  const r = spawnSync(process.execPath, [join(HERE, "compare.mjs")], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, GO_VERIFY: "/nonexistent/vitni-go" },
  });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /IMPL-UNSPAWNABLE go/);
});
