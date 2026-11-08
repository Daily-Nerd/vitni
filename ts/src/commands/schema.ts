/**
 * Input schema: the single owner of which members each command reads from its
 * stdin object, which of them are required, and their JSON types. Counterpart
 * of Go's internal/fields + internal/wire.
 *
 * Rules (the same in Go):
 *  - member names are exact and case-sensitive; a name that differs only in case
 *    is an unknown member and is ignored;
 *  - a JSON null is "not present" for every typed member; the one exception is a
 *    member of type `any` (jcs `value`), where the key being there is presence,
 *    because null is a value of its domain;
 *  - a required member that is not present, or any member of the wrong JSON type,
 *    makes the input invalid: the CLI answers invalid_input, a command error and
 *    never a verdict. This holds for the WHOLE typed part of the input, not only
 *    the entry a receipt resolves to (verify.keys is walked entirely);
 *  - unknown members are ignored, so the input can grow.
 *
 * The text has already passed parseStrict and the top level is an object. What
 * each command then does with a member (hashstring algo must be "sha2-256",
 * sign kid absent is kid_required, keygen seed_b64 non-string is invalid_seed)
 * stays in the command: this table decides shape, not meaning.
 */

type Obj = Record<string, unknown>;
type MemberType = 'string' | 'object' | 'string[]' | 'any';

interface Member {
  name: string;
  type: MemberType;
  required: boolean;
}

const str = (name: string, required = false): Member => ({ name, type: 'string', required });
const obj = (name: string, required = false): Member => ({ name, type: 'object', required });

function isObject(v: unknown): v is Obj {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function has(o: Obj, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, name);
}

function typeOk(v: unknown, type: MemberType): boolean {
  switch (type) {
    case 'string': return typeof v === 'string';
    case 'object': return isObject(v);
    case 'string[]': return Array.isArray(v) && v.every((x) => typeof x === 'string');
    case 'any': return true;
  }
}

function memberOk(o: Obj, m: Member): boolean {
  if (!has(o, m.name)) return !m.required;
  const v = o[m.name];
  if (v === null && m.type !== 'any') return !m.required;
  return typeOk(v, m.type);
}

function membersOk(o: Obj, members: readonly Member[]): boolean {
  return members.every((m) => memberOk(o, m));
}

/** A registry entry: kty, crv, x, y, alg, status are each a string, null or absent. */
const REGISTRY_ENTRY: readonly Member[] = ['kty', 'crv', 'x', 'y', 'alg', 'status'].map((n) => str(n));
const POLICY: readonly Member[] = [str('expected_binding'), str('expected_method')];

/** keys: object | null; every performer an object | null; every entry an object | null. */
function keysTreeOk(o: Obj): boolean {
  const keys = o['keys'];
  if (keys === undefined || keys === null) return true;
  if (!isObject(keys)) return false;
  for (const performer of Object.values(keys)) {
    if (performer === null) continue;
    if (!isObject(performer)) return false;
    for (const entry of Object.values(performer)) {
      if (entry === null) continue;
      if (!isObject(entry) || !membersOk(entry, REGISTRY_ENTRY)) return false;
    }
  }
  return true;
}

function policyOk(o: Obj): boolean {
  const policy = o['policy'];
  if (policy === undefined || policy === null) return true;
  return isObject(policy) && membersOk(policy, POLICY);
}

/** a2a: artifact.parts is a required array of objects with typed kind and file. */
function artifactOk(o: Obj): boolean {
  const artifact = o['artifact'] as Obj;
  const parts = artifact['parts'];
  if (!Array.isArray(parts)) return false;
  return parts.every((part) => {
    if (!isObject(part) || !memberOk(part, str('kind'))) return false;
    const file = part['file'];
    if (file === undefined || file === null) return true;
    return isObject(file) && membersOk(file, [str('bytes'), str('uri'), str('mimeType'), str('name')]);
  });
}

interface CommandSchema {
  members: readonly Member[];
  /** Deep checks that run after the members are known to be well-typed. */
  deep?: (o: Obj) => boolean;
}

const SCHEMAS: Record<string, CommandSchema> = {
  jcs: { members: [{ name: 'value', type: 'any', required: true }] },
  hashstring: { members: [str('algo', true), str('digest_hex', true)] },
  digest: { members: [str('bytes_b64', true)] },
  'receipt-id': { members: [obj('receipt', true)] },
  'sse-outputs-hash': { members: [str('raw_b64', true), str('mode', true)] },
  'cost-canon': { members: [obj('cost', true)] },
  verify: {
    members: [str('signed_receipt'), obj('keys'), obj('policy')],
    deep: (o) => keysTreeOk(o) && policyOk(o),
  },
  'verify-chain': {
    members: [{ name: 'receipts', type: 'string[]', required: false }, obj('keys'), obj('policy')],
    deep: (o) => keysTreeOk(o) && policyOk(o),
  },
  'a2a-artifact-hash': { members: [obj('artifact', true)], deep: artifactOk },
  sign: { members: [obj('receipt', true), str('kid'), str('private_key_b64')] },
  // keygen judges seed_b64 itself (a non-string is invalid_seed, an unknown
  // member is invalid_input): its contract is pinned by the keygen-* vectors.
  keygen: { members: [] },
};

/**
 * Whether `input` has the shape `command` requires. The caller (cli.ts) owns
 * the two preconditions: `command` is a known command and `input` is the
 * parsed top-level object.
 */
export function validateInput(command: string, input: Obj): boolean {
  const schema = SCHEMAS[command];
  return membersOk(input, schema.members) && (schema.deep?.(input) ?? true);
}
