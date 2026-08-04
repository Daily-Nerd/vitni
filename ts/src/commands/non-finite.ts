/**
 * Non-finite number detection, shared by cli.ts (stdin-level guard) and
 * sse-outputs-hash.ts (sse-jsonrpc inner-result guard, #58).
 *
 * JSON.parse admits 1e400 as Infinity; serializing it would emit the bytes
 * "null" — silent corruption. Go rejects non-finite at parse (jcs.Transform,
 * go/vitni.go:28); both call sites here match it. Lives in its own module
 * rather than being exported from cli.ts, which sse-outputs-hash.ts is
 * imported BY (cli.ts -> sse-outputs-hash.ts) — importing back from cli.ts
 * would cycle.
 */
export function hasNonFinite(v: unknown): boolean {
  if (typeof v === 'number') return !Number.isFinite(v);
  if (Array.isArray(v)) return v.some(hasNonFinite);
  if (v !== null && typeof v === 'object') return Object.values(v).some(hasNonFinite);
  return false;
}
