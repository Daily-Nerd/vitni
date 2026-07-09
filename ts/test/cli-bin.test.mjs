/**
 * CLI bin executability tests.
 *
 * The npm `bin` (vitni-verify -> dist/cli.js) is invoked directly by the
 * OS, not via `node dist/cli.js`. Without a `#!/usr/bin/env node` shebang the
 * shell tries to run the JS as a shell script and fails. This regressed
 * silently because the vector tests import the module and never exec the bin.
 *
 * STRICT TDD: written before the shebang fix — fails until cli.ts carries it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '../dist/cli.js');

test('dist/cli.js starts with a node shebang', () => {
  const firstLine = readFileSync(CLI, 'utf8').split('\n', 1)[0];
  assert.equal(
    firstLine,
    '#!/usr/bin/env node',
    `bin entry must start with a node shebang so the installed binary is directly executable (got: ${JSON.stringify(firstLine)})`
  );
});

test('the bin runs directly (executable via shebang), not just via `node`', () => {
  // Make it executable like npm does on install, then run it WITHOUT a `node`
  // prefix — this is what `vitni-verify <cmd>` does for an installed user.
  chmodSync(CLI, 0o755);
  const out = execFileSync(CLI, ['jcs'], {
    input: JSON.stringify({ value: { b: 1, a: 2 } }),
    encoding: 'utf8',
  });
  const parsed = JSON.parse(out);
  assert.ok(typeof parsed.canonical_hex === 'string' && parsed.byte_len > 0, 'jcs via direct bin exec should return a canonical result');
});
