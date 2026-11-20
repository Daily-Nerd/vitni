// Guards on the binary-release jobs of .github/workflows/release.yml: the
// build must stay reproducible and checked, assets must never be silently
// overwritten, and permissions must stay scoped per job. Text-level on
// purpose: these are the properties that must survive an edit.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8");

// The text of one top-level job, from `  <name>:` to the next job or EOF.
// Comment lines are dropped so prose never trips a guard.
function job(name) {
  const m = WORKFLOW.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-z][a-z0-9-]*:\\n|(?![\\s\\S]))`, "m"));
  assert.ok(m, `job "${name}" not found`);
  return m[1].split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
}

test("job() isolates one job", () => {
  assert.match(job("publish-npm"), /npm publish --provenance/);
  assert.doesNotMatch(job("publish-npm"), /go build/);
  assert.throws(() => job("no-such-job"), /not found/);
});

test("the Go toolchain is pinned to an exact patch version, in one place", () => {
  const pins = [...WORKFLOW.matchAll(/^  GO_VERSION: "(\d+\.\d+\.\d+)"$/gm)];
  assert.equal(pins.length, 1, "exactly one GO_VERSION pin, with major.minor.patch");
  assert.match(job("build-binaries"), /go-version: \$\{\{ env\.GO_VERSION \}\}/);
  assert.doesNotMatch(WORKFLOW, /go-version: "/, "no literal go-version next to the pin");
});

test("the binary is built static and trimmed, twice, and the hashes must match", () => {
  const b = job("build-binaries");
  assert.match(b, /CGO_ENABLED=0/);
  assert.match(b, /-trimpath/);
  assert.match(b, /-ldflags='-s -w -buildid='/);
  assert.match(b, /-buildvcs=false/);
  assert.match(b, /sha256sum/);
  assert.match(b, /differ/, "a differing hash must produce an explicit failure");
  assert.match(b, /GOCACHE/, "each build needs its own cache or the second build proves nothing");
});

test("no gate can be made non-fatal and no asset is overwritten", () => {
  assert.doesNotMatch(WORKFLOW, /continue-on-error/);
  assert.doesNotMatch(WORKFLOW, /--clobber/);
  assert.doesNotMatch(WORKFLOW, /\|\| true/);
});

test("permissions are scoped per job", () => {
  const b = job("build-binaries");
  assert.match(b, /id-token: write/);
  assert.match(b, /attestations: write/);
  assert.match(b, /contents: read/);
  assert.doesNotMatch(b, /contents: write/);
  const p = job("release-assets");
  assert.match(p, /contents: write/);
  assert.doesNotMatch(p, /id-token|attestations/);
  assert.match(job("go-release"), /permissions: \{\}/);
});

test("provenance is attested for each binary and the verify text is published", () => {
  assert.match(job("build-binaries"), /uses: actions\/attest-build-provenance@/);
  const p = job("release-assets");
  assert.match(p, /gh attestation verify/);
  assert.match(p, /--repo Daily-Nerd\/vitni/);
  assert.match(p, /SHA256SUMS/);
});

test("the npm escape hatch survives and a dispatch must name something to do", () => {
  assert.match(WORKFLOW, /publish_ref:/);
  assert.match(WORKFLOW, /go_tag:/);
  assert.match(job("publish-npm"), /github\.event\.inputs\.publish_ref != ''/);
  assert.match(job("dispatch-inputs"), /exit 1/);
});

test("the release workflow carries no em-dash", () => {
  assert.ok(!WORKFLOW.includes(String.fromCharCode(0x2014)));
});
