/**
 * scanText: the one raw-text pass of the stdin gate (depth, lone-surrogate
 * escapes, non-finite numbers). It runs on text that is not yet known to be
 * valid JSON, so the equivalence tests below compare the FINAL gate answer
 * (ok / not ok) against a private copy of the previous value-walk gate.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { stdinBytes } from '../../conformance/harness.mjs';

const DIST = new URL('../dist', import.meta.url).pathname;
const VECTORS = new URL('../../conformance/vectors', import.meta.url).pathname;
const { scanText, parseStrict, withinDepth, decodeUtf8Strict, hasDuplicateKeys, MAX_DEPTH } = await import(
  `${DIST}/commands/strict-json.js`
);

const ALL = { surrogates: true, nonFinite: true };
const SURR = { surrogates: true, nonFinite: false };
const NF = { surrogates: false, nonFinite: true };
const NONE = { surrogates: false, nonFinite: false };

const SCAN_CASES = [
  // lone-surrogate escapes
  ['valid pair', '{"a":"\\ud83d\\ude00"}', SURR, true],
  ['lone high', '{"a":"\\ud800"}', SURR, false],
  ['lone low', '{"a":"\\udc00"}', SURR, false],
  ['high then non-low escape', '{"a":"\\ud800\\u0041"}', SURR, false],
  ['high then plain char', '{"a":"\\ud800x"}', SURR, false],
  ['high then other escape', '{"a":"\\ud800\\n"}', SURR, false],
  ['high at end of string', '{"a":"x\\ud800"}', SURR, false],
  ['high then high', '{"a":"\\ud800\\ud800"}', SURR, false],
  ['reversed pair', '{"a":"\\ude00\\ud83d"}', SURR, false],
  ['escaped backslash is not an escape', '{"a":"\\\\ud800"}', SURR, true],
  ['escaped backslash then real escape', '{"a":"\\\\\\ud800"}', SURR, false],
  ['lone high in key', '{"\\ud800":1}', SURR, false],
  ['lone low in key', '{"\\udc00":1}', SURR, false],
  ['valid pair in key', '{"\\ud83d\\ude00":1}', SURR, true],
  ['pair does not span two strings', '["\\ud83d","\\ude00"]', SURR, false],
  ['pair does not span a key and its value', '{"\\ud83d":"\\ude00"}', SURR, false],
  ['upper-case hex lone high', '{"a":"\\uD800"}', SURR, false],
  ['upper-case hex valid pair', '{"a":"\\uD83D\\uDE00"}', SURR, true],
  ['mixed-case hex valid pair', '{"a":"\\uD83d\\uDe00"}', SURR, true],
  ['bmp escape next to a pair', '{"a":"\\u0041\\ud83d\\ude00\\u0042"}', SURR, true],
  ['boundary d7ff is not a surrogate', '{"a":"\\ud7ff"}', SURR, true],
  ['boundary e000 is not a surrogate', '{"a":"\\ue000"}', SURR, true],
  ['boundary dbff then dc00 is a pair', '{"a":"\\udbff\\udc00"}', SURR, true],
  ['boundary dbff then dfff is a pair', '{"a":"\\udbff\\udfff"}', SURR, true],
  ['surrogate check off', '{"a":"\\ud800"}', NONE, true],
  // non-finite numbers
  ['1e400', '{"a":1e400}', NF, false],
  ['-1e400', '{"a":-1e400}', NF, false],
  ['1E400', '{"a":1E400}', NF, false],
  ['1e+400', '{"a":1e+400}', NF, false],
  ['1e308 is finite', '{"a":1e308}', NF, true],
  ['1.7976931348623157e308 is finite', '{"a":1.7976931348623157e308}', NF, true],
  ['1e-400 underflows to a finite zero', '{"a":1e-400}', NF, true],
  ['negative zero', '{"a":-0}', NF, true],
  ['negative zero fraction', '{"a":-0.0e0}', NF, true],
  ['overflowing integer without exponent', `{"a":1${'0'.repeat(400)}}`, NF, false],
  ['top-level array of numbers', '[1,2,3e400]', NF, false],
  ['non-finite in a nested array', '{"a":[{"b":1e999}]}', NF, false],
  ['number at the very end of the text', '1e400', NF, false],
  ['number inside a string is ignored', '{"a":"1e400"}', NF, true],
  ['number inside a key is ignored', '{"1e400":1}', NF, true],
  ['number after an escaped quote stays in the string', '{"a":"\\"1e400"}', NF, true],
  ['true / false / null contain e but are not numbers', '[true,false,null]', NF, true],
  ['non-finite check off', '{"a":1e400}', NONE, true],
  // depth
  ['depth 128 ok', '['.repeat(128) + ']'.repeat(128), NONE, true],
  ['depth 129 rejected', '['.repeat(129) + ']'.repeat(129), NONE, false],
  ['brackets inside a string do not count', '{"a":"' + '['.repeat(500) + '"}', ALL, true],
];

for (const [name, text, opts, want] of SCAN_CASES) {
  test(`scanText: ${name}`, () => assert.equal(scanText(text, opts), want));
}

test('scanText: depth only mode never judges text that is not JSON (sse-jsonrpc relies on it)', () => {
  // Skipped-vs-rejected: with both checks off, a malformed escape or a
  // garbage number token must pass the scan, exactly as withinDepth did.
  assert.equal(scanText('"\\ud800', NONE), true);
  assert.equal(scanText('"\\uZZZZ"', NONE), true);
  assert.equal(scanText('-e-e-+', NONE), true);
  assert.equal(withinDepth('"\\ud800'), true);
  assert.equal(withinDepth('['.repeat(MAX_DEPTH + 1)), false);
  assert.equal(withinDepth('['.repeat(MAX_DEPTH)), true);
});

// ---------------------------------------------------------------------------
// Equivalence with the previous gate. Private copy of the old value walks.
// ---------------------------------------------------------------------------

const LONE = /[\uD800-\uDFFF]/u;
function oldHasLoneSurrogate(root) {
  const stack = [root];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === 'string') {
      if (LONE.test(v)) return true;
    } else if (Array.isArray(v)) {
      for (const x of v) stack.push(x);
    } else if (v !== null && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        if (LONE.test(k)) return true;
        stack.push(x);
      }
    }
  }
  return false;
}
function oldHasNonFinite(v) {
  if (typeof v === 'number') return !Number.isFinite(v);
  if (Array.isArray(v)) return v.some(oldHasNonFinite);
  if (v !== null && typeof v === 'object') return Object.values(v).some(oldHasNonFinite);
  return false;
}
function oldOk(bytes, p) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return false;
  const text = decodeUtf8Strict(bytes);
  if (text === null) return false;
  if (!withinDepth(text)) return false;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (oldHasLoneSurrogate(value)) return false;
  if (p.rejectDuplicates && hasDuplicateKeys(text)) return false;
  if (p.rejectNonFinite && oldHasNonFinite(value)) return false;
  return true;
}

const POLICIES = [
  { rejectDuplicates: false, rejectNonFinite: false },
  { rejectDuplicates: true, rejectNonFinite: false },
  { rejectDuplicates: false, rejectNonFinite: true },
  { rejectDuplicates: true, rejectNonFinite: true },
];

function sameAnswer(bytes, label) {
  for (const p of POLICIES) {
    assert.equal(parseStrict(bytes, p).ok, oldOk(bytes, p), `${label} ${JSON.stringify(p)}`);
  }
}

test('equivalence: every conformance vector input gets the same gate answer', () => {
  const files = fs.readdirSync(VECTORS).filter((f) => f.endsWith('.json') && !f.startsWith('_'));
  let n = 0;
  for (const f of files) {
    const vec = JSON.parse(fs.readFileSync(`${VECTORS}/${f}`, 'utf8'));
    let bytes;
    try {
      bytes = stdinBytes(vec);
    } catch {
      continue;
    }
    sameAnswer(bytes, f);
    n++;
  }
  assert.ok(n > 300, `only ${n} vectors reached the gate`);
});

test('equivalence: the scan table above gets the same gate answer', () => {
  for (const [name, text] of SCAN_CASES) sameAnswer(Buffer.from(text, 'utf8'), name);
});

test('equivalence: deterministic token soup, valid and invalid text alike', () => {
  const TOKENS = [
    '"', '"', '"', '\\', '\\\\', '\\"', '\\ud800', '\\udc00', '\\uD83D', '\\uDE00', '\\u0041', '\\n', '\\uZZZZ',
    'a', 'e', ' ', ':', ',', '[', ']', '{', '}', '{"k":', '["x",', '"k":',
    '1', '-', '-0', '0.5', '1e400', '-1e400', '1e308', '1E+2', '1e-400', 'true', 'null', '1e',
  ];
  let seed = 0x9e3779b9;
  const rnd = (m) => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed % m;
  };
  let valid = 0;
  for (let i = 0; i < 20000; i++) {
    let s = '';
    const len = 1 + rnd(14);
    for (let j = 0; j < len; j++) s += TOKENS[rnd(TOKENS.length)];
    // Wrap a share of the soup in a string or array so many cases are valid JSON.
    const text = [s, `["${s}"]`, `{"${s}":1}`, `[${s}]`, `{"a":"${s}"}`][rnd(5)];
    const bytes = Buffer.from(text, 'utf8');
    sameAnswer(bytes, JSON.stringify(text));
    if (oldOk(bytes, POLICIES[0])) valid++;
  }
  assert.ok(valid > 500, `soup produced only ${valid} valid texts`);
});
