#!/usr/bin/env node
// vitni conformance harness CLI: runs every vector through every registered
// verifier (Go and TypeScript always, Python when PY_VERIFY is set) and asserts
// byte-identical output, anchors, profile scope and coverage floors. REQUIRE_IMPLS
// (comma separated, CI sets go,ts,py) makes a missing impl a failure. The logic
// lives in harness.mjs (runSuite); this file only turns the environment into
// options, prints the report and sets the exit code.
//
//   GO_VERIFY="./bin/vitni-verify-go" TS_VERIFY="node ts/dist/cli.js" node conformance/compare.mjs
import {
  defaultImpls, requiredImpls, runSuite, formatReport, loadJson,
  DEFAULT_VECTORS, DEFAULT_CATALOG, DEFAULT_FLOORS,
} from "./harness.mjs";

const res = runSuite({
  impls: defaultImpls(process.env),
  vectorsDir: DEFAULT_VECTORS,
  catalog: loadJson(DEFAULT_CATALOG),
  floors: loadJson(DEFAULT_FLOORS),
  required: requiredImpls(process.env),
});
console.log(formatReport(res));
process.exit(res.ok ? 0 : 1);
