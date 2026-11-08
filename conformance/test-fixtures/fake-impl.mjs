#!/usr/bin/env node
// A scriptable fake verifier for the harness self-tests. It is test
// infrastructure: it answers a vector by echoing the vector's anchor, found by
// matching the exact stdin bytes it receives.
//
//   node fake-impl.mjs <mode> <subcommand>
//
// Configuration (environment, per spawned impl):
//   FAKE_VECTORS         directory of vector files the fake can answer
//   FAKE_DECLARED        JSON array: the atoms `profiles` declares
//                        (default: every gating atom of test-fixtures/catalog.json)
//   FAKE_DECLINE_CMDS    comma list: commands declined with cmd:<command>
//   FAKE_DECLINE_VECTOR  one vector name declined with cmd:<its command> only
//   FAKE_FORCE_DECLINE   an atom: every vector is declined naming it, in scope or not
//
// Modes:
//   echo-anchor        honest: answers in-scope vectors, declines out-of-scope
//                      ones with unsupported_profile
//   silent-answer      answers every vector, in scope or not
//   silent-skip        prints nothing for an out-of-scope vector
//   wrong-profile      declines out-of-scope vectors naming an atom that is not missing
//   no-profile-member  declines out-of-scope vectors without a `profile` member
//   extra-member       declines with an extra member next to `profile`
//   decline-one        honest, plus FAKE_DECLINE_VECTOR declined with cmd:
//   declare-unknown    `profiles` declares an atom the catalog does not list
//   declare-nongating  `profiles` declares a non-gating atom
//   crash              every vector exits 3 (profiles still works)
//   bad-utf8           answers with an invalid UTF-8 byte
//   different-answer   answers with the anchor plus one extra member (bytes differ)
//
// A vector may carry `fake_output` (any JSON value) which an answering fake
// prints instead of the anchor; with neither, the fake prints invalid_input.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const [mode, sub] = process.argv.slice(2);
const DEFAULT_DECLARED = ["alg:ES256", "alg:EdDSA", "canon:b64-strict", "canon:jcs"];
const declared = process.env.FAKE_DECLARED ? JSON.parse(process.env.FAKE_DECLARED) : DEFAULT_DECLARED;

function out(text) { process.stdout.write(text + "\n"); }

if (sub === "profiles") {
  const list = [...declared];
  if (mode === "declare-unknown") list.push("alg:Nope");
  if (mode === "declare-nongating") list.push("binding:mcp");
  out(JSON.stringify(list.sort()));
  process.exit(0);
}

const stdin = readFileSync(0);
function stdinBytes(v) {
  if (v.input_raw_b64 !== undefined) return Buffer.from(v.input_raw_b64, "base64");
  if (v.input_raw !== undefined) return Buffer.from(v.input_raw, "utf8");
  return Buffer.from(JSON.stringify(v.input), "utf8");
}
let vec = null;
for (const f of readdirSync(process.env.FAKE_VECTORS)) {
  if (!f.endsWith(".json") || f.startsWith("_")) continue;
  const v = JSON.parse(readFileSync(join(process.env.FAKE_VECTORS, f), "utf8"));
  if (v.command === sub && stdinBytes(v).equals(stdin)) { vec = v; break; }
}
if (vec === null) { out(JSON.stringify({ error: "invalid_input" })); process.exit(0); }

if (mode === "crash") { process.stderr.write("boom\n"); process.exit(3); }
if (mode === "bad-utf8") { process.stdout.write(Buffer.from([0x7b, 0xff, 0x7d, 0x0a])); process.exit(0); }

const gating = new Set(JSON.parse(readFileSync(join(HERE, "catalog.json"), "utf8")).atoms
  .filter((a) => a.gating).map((a) => a.id));
const missing = (vec.profiles ?? []).filter((a) => gating.has(a) && !declared.includes(a));
const declinedCmd = (process.env.FAKE_DECLINE_CMDS ?? "").split(",").filter(Boolean).includes(sub)
  || (mode === "decline-one" && process.env.FAKE_DECLINE_VECTOR === vec.name);

function decline(profile) { out(JSON.stringify({ error: "unsupported_profile", profile })); process.exit(0); }
function answer() {
  const body = vec.fake_output ?? vec.anchor ?? { error: "invalid_input" };
  out(JSON.stringify(mode === "different-answer" ? { ...body, extra: 1 } : body));
  process.exit(0);
}

if (process.env.FAKE_FORCE_DECLINE) decline(process.env.FAKE_FORCE_DECLINE);
if (mode === "silent-answer") answer();
if (declinedCmd) decline(`cmd:${sub}`);
if (missing.length > 0) {
  if (mode === "silent-skip") process.exit(0);
  if (mode === "wrong-profile") decline("binding:local");
  if (mode === "no-profile-member") { out(JSON.stringify({ error: "unsupported_profile" })); process.exit(0); }
  if (mode === "extra-member") { out(JSON.stringify({ error: "unsupported_profile", note: "x", profile: missing[0] })); process.exit(0); }
  decline(missing[0]);
}
answer();
