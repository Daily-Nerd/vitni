/**
 * The exact stdin bytes a conformance vector pins, as a Buffer. A vector uses
 * exactly one of three forms:
 *   input          structured JSON, serialized here
 *   input_raw      the exact stdin text (duplicate keys, ...)
 *   input_raw_b64  standard base64 of the exact stdin BYTES (invalid UTF-8, BOM,
 *                  anything a JS string cannot carry)
 * A present-but-empty value is EMPTY stdin, never "absent": presence is tested
 * with `!== undefined`, not truthiness. Mirrors stdinBytes in compare.mjs and
 * vecStdin in go/cmd/vitni-verify/main_test.go.
 */
export function vectorStdin(vec) {
  const forms = ['input', 'input_raw', 'input_raw_b64'].filter((k) => vec[k] !== undefined);
  if (forms.length !== 1) {
    throw new Error(`${vec.name}: exactly one of input, input_raw, input_raw_b64 required, found [${forms.join(', ')}]`);
  }
  if (vec.input_raw_b64 !== undefined) return Buffer.from(vec.input_raw_b64, 'base64');
  if (vec.input_raw !== undefined) return Buffer.from(vec.input_raw, 'utf8');
  return Buffer.from(JSON.stringify(vec.input), 'utf8');
}
