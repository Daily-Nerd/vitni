// Build artifacts must never be tracked. A built Go binary (4 MB) and a .pyc
// were each committed once by running a build or an interpreter inside the
// tree with no ignore rule in the way. This test checks the tracked tree
// (git ls-files), so an ignored-but-present local build output never trips it.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MAX_BYTES = 1_000_000;

// Tracked files allowed to exceed MAX_BYTES, by exact repo-relative path.
// Empty on purpose: add an entry only for vendored data, with the reason.
export const SIZE_ALLOWLIST = new Set([]);

const trackedFiles = () =>
  execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, maxBuffer: 1 << 28 })
    .toString("utf8")
    .split("\0")
    .filter(Boolean);

// Returns a label when the bytes start like an executable image, else null.
export function binaryKind(head) {
  const b = Buffer.from(head);
  if (b.length >= 4) {
    if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return "ELF";
    const m = b.readUInt32BE(0);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xcafebabf].includes(m)) {
      return "Mach-O";
    }
  }
  if (b.length >= 0x40 && b[0] === 0x4d && b[1] === 0x5a) {
    const off = b.readUInt32LE(0x3c);
    if (off + 4 <= b.length && b.toString("latin1", off, off + 4) === "PE\0\0") return "PE";
  }
  return null;
}

function readHead(path) {
  const fd = openSync(path, "r");
  try {
    if (!fstatSync(fd).isFile()) return null;
    const buf = Buffer.alloc(4096);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n);
  } finally {
    closeSync(fd);
  }
}

test("the detector recognises ELF, Mach-O and PE headers and ignores text", () => {
  assert.equal(binaryKind(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1])), "ELF");
  assert.equal(binaryKind(Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 7, 0])), "Mach-O");
  assert.equal(binaryKind(Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0])), "Mach-O");
  const pe = Buffer.alloc(0x80);
  pe.write("MZ", 0, "latin1");
  pe.writeUInt32LE(0x40, 0x3c);
  pe.write("PE\0\0", 0x40, "latin1");
  assert.equal(binaryKind(pe), "PE");
  assert.equal(binaryKind(Buffer.from("MZ is a prefix, not a binary")), null);
  assert.equal(binaryKind(Buffer.from("package main\n")), null);
});

test("no tracked file is an executable binary", () => {
  const found = [];
  for (const f of trackedFiles()) {
    const head = readHead(join(ROOT, f));
    const kind = head && binaryKind(head);
    if (kind) found.push(`${f} (${kind})`);
  }
  assert.deepEqual(found, [], "tracked executable binaries; build outside the tree and ignore the output");
});

test("no tracked .pyc file or __pycache__ directory", () => {
  const found = trackedFiles().filter((f) => /\.pyc$/.test(f) || /(^|\/)__pycache__\//.test(f));
  assert.deepEqual(found, [], "tracked Python bytecode");
});

test("no tracked file over 1 MB unless allowlisted", () => {
  const found = [];
  for (const f of trackedFiles()) {
    const fd = openSync(join(ROOT, f), "r");
    try {
      const st = fstatSync(fd);
      if (st.isFile() && st.size > MAX_BYTES && !SIZE_ALLOWLIST.has(f)) found.push(`${f} (${st.size} bytes)`);
    } finally {
      closeSync(fd);
    }
  }
  assert.deepEqual(found, [], "oversized tracked files");
});
