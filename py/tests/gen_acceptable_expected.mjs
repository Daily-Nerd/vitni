// Regenerates py/tests/acceptable_expected.json: ONE pinned outcome per
// Wycheproof `acceptable` Ed25519 case, taken from Node's crypto (Go's
// crypto/ed25519 agrees on all 29, checked when this file was added). The
// Python verdict must equal the pin, so verdicts stay identical across
// verifiers. Usage: node py/tests/gen_acceptable_expected.mjs
import fs from "node:fs";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "..", "..");
const doc = JSON.parse(fs.readFileSync(path.join(root, "conformance/third_party/wycheproof/ed25519_test.json"), "utf8"));
// DER SubjectPublicKeyInfo prefix for an Ed25519 public key.
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const out = {};
for (const g of doc.testGroups) {
  const key = crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(g.publicKey.pk, "hex")]), format: "der", type: "spki" });
  for (const t of g.tests) {
    if (t.result !== "acceptable") continue;
    out[String(t.tcId)] = crypto.verify(null, Buffer.from(t.msg, "hex"), key, Buffer.from(t.sig, "hex"));
  }
}
const sorted = Object.fromEntries(Object.entries(out).sort(([a], [b]) => Number(a) - Number(b)));
fs.writeFileSync(path.join(here, "acceptable_expected.json"), JSON.stringify(sorted, null, 2) + "\n");
