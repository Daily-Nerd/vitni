/**
 * Single-owner guard: every base64url DECODE in the published sources goes
 * through decodeB64UrlStrict (decode.ts). A second `Buffer.from(x, 'base64url')`
 * is a lenient decoder (Node drops partial chars and masks trailing bits).
 * Encoding (`buf.toString('base64url')`) is fine anywhere. The demo/server
 * files are excluded from the published bundle and only decode strings they
 * just signed themselves.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = new URL('../src', import.meta.url).pathname;

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]
  );
}

test('no base64url decode outside decode.ts', () => {
  const offenders = walk(SRC)
    .filter((f) => f.endsWith('.ts'))
    .filter((f) => !/\/decode\.ts$/.test(f) && !/\/(demo|server)\.ts$/.test(f))
    .filter((f) =>
      readFileSync(f, 'utf8')
        .split('\n')
        .some((l) => /Buffer\.from\(.*['"]base64url['"]/.test(l))
    );
  assert.deepEqual(offenders, []);
});

test('verify and verify-chain never JSON.parse JWS header/payload directly', () => {
  // decodeJsonObject (strict-json.ts) is the one entry for those bytes.
  for (const f of ['commands/verify.ts', 'commands/verify-chain.ts']) {
    const src = readFileSync(join(SRC, f), 'utf8');
    const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
    assert.ok(!/JSON\.parse\(/.test(code), `${f} calls JSON.parse directly`);
  }
});
