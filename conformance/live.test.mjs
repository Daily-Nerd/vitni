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

test("S1.23 floors.json holds Go and TS at all vectors (not an integer copy of the count)", () => {
  assert.deepEqual(JSON.parse(readFileSync(join(HERE, "floors.json"), "utf8")), { go: "all", ts: "all" });
});

test("S1.25 compare.mjs prints impls, the computed vector count and a clean pass for Go and TS", () => {
  requireBuilt();
  const r = spawnSync(process.execPath, [join(HERE, "compare.mjs")], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, PY_VERIFY: "" },
  });
  const n = readdirSync(DEFAULT_VECTORS).filter((f) => f.endsWith(".json") && !f.startsWith("_")).length;
  assert.equal(r.status, 0, r.stdout.split("\n").filter((l) => l.startsWith("* ")).join("\n"));
  assert.match(r.stdout, /^impls: go ts$/m);
  assert.match(r.stdout, new RegExp(`^vectors: ${n}$`, "m"));
  assert.match(r.stdout, new RegExp(`^${n}/${n} passed\\.$`, "m"));
  // Go and TS are in scope for every vector: each matrix cell is k/k
  const cells = r.stdout.split("--- coverage ---")[1].split(/\n\n/)[1].trim().split("\n").slice(1);
  assert.ok(cells.length > 5);
  for (const row of cells) {
    for (const cell of row.trim().split(/\s+/).slice(1)) {
      const [a, b] = cell.split("/");
      assert.equal(a, b, `partial scope in row: ${row}`);
    }
  }
});

test("compare.mjs exits 1 and names the failure when an impl cannot be spawned", () => {
  const r = spawnSync(process.execPath, [join(HERE, "compare.mjs")], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, GO_VERIFY: "/nonexistent/vitni-go" },
  });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /IMPL-UNSPAWNABLE go/);
});
