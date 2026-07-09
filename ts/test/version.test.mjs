/**
 * The protocol version string must come from ONE shared constant, mirroring
 * Go's `vitni.Version`. It was previously hardcoded in three places
 * (sign command + MCP/A2A middleware), which could silently drift when the
 * protocol version bumps.
 *
 * STRICT TDD: written before the constant exists — fails until VERSION is added.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST = join(__dirname, '../dist');
const SRC = join(__dirname, '../src');

const { VERSION } = await import(`${DIST}/version.js`);

test('VERSION is the pinned protocol version string', () => {
  assert.equal(VERSION, 'vitni/0.2');
});

test('VERSION is re-exported from the package index', async () => {
  const idx = await import(`${DIST}/index.js`);
  assert.equal(idx.VERSION, 'vitni/0.2');
});

test('the protocol version is not hardcoded outside version.ts', () => {
  // Any source file that stamps a receipt must import VERSION, not inline the
  // literal — this guards against re-introducing the drift.
  for (const rel of ['commands/sign.ts', 'mcp/vitni-middleware.ts', 'a2a/vitni-a2a-middleware.ts']) {
    const text = readFileSync(join(SRC, rel), 'utf8');
    assert.ok(
      !/['"](?:vitni\/0\.2|veritrail\/0\.1)['"]/.test(text),
      `${rel} hardcodes the protocol version string; import VERSION from version.ts instead`
    );
  }
});
