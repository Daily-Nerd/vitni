/**
 * a2a-artifact-hash command — A2A artifact canonicalization → outputs_hash (design §14).
 *
 * A2A does not define artifact-level canonicalization, so Vitni defines it.
 * Each Part (preserving array order) maps to a canonical descriptor:
 *   - text → { kind:"text", text }
 *   - data → { kind:"data", data }
 *   - file inline (bytes present) →
 *       { kind:"file", digest: multihash(decoded bytes), mimeType:<m|null>, name:<n|null> }
 *   - file by-uri (uri present, no bytes) →
 *       { kind:"file", uri, declared_digest:<hashstr|null>, mimeType:<m|null>, name:<n|null> }
 *   - neither bytes nor uri, or unknown kind → { error:"unsupported_part" }.
 *
 * descriptor = { parts: [ <descriptor_0>, ... ] }
 * descriptor_hex = hex(JCS(descriptor)); outputs_hash = multihash(JCS(descriptor)).
 *
 * A by-uri file's referenced bytes are NEVER dereferenced (§4.4) — only the
 * declared_digest is carried.
 */
import { jcsBytes } from './jcs.js';
import { digestBytes } from './digest.js';
import { decodeStdBase64 } from './decode.js';

interface A2AFile {
  bytes?: string;
  uri?: string;
  declared_digest?: string | null;
  mimeType?: string | null;
  name?: string | null;
}

interface A2APart {
  kind?: string;
  text?: unknown;
  data?: unknown;
  file?: A2AFile;
}

export interface A2AArtifactHashInput {
  artifact: { parts: A2APart[] };
}

export interface A2AArtifactHashOutput {
  outputs_hash: string;
  descriptor_hex: string;
}

type ErrorResult = { error: string };

/** Coerce an optional metadata field to its value or null (present-as-null). */
function orNull<T>(v: T | undefined | null): T | null {
  return v === undefined ? null : v;
}

/**
 * Map one A2A Part to its canonical descriptor, or return an error marker.
 */
function partToDescriptor(part: A2APart): Record<string, unknown> | ErrorResult {
  const kind = part.kind;

  if (kind === 'text') {
    return { kind: 'text', text: part.text };
  }

  if (kind === 'data') {
    return { kind: 'data', data: part.data };
  }

  if (kind === 'file') {
    const file = part.file;
    if (!file) {
      return { error: 'unsupported_part' };
    }
    if (typeof file.bytes === 'string') {
      // inline: hash the bytes, never embed them
      const decoded = decodeStdBase64(file.bytes);
      if (decoded === null) {
        return { error: 'invalid_input' };
      }
      return {
        kind: 'file',
        digest: digestBytes(decoded),
        mimeType: orNull(file.mimeType),
        name: orNull(file.name),
      };
    }
    if (typeof file.uri === 'string') {
      // by-reference: never dereferenced (§4.4)
      return {
        kind: 'file',
        uri: file.uri,
        declared_digest: orNull(file.declared_digest),
        mimeType: orNull(file.mimeType),
        name: orNull(file.name),
      };
    }
    // file with neither bytes nor uri
    return { error: 'unsupported_part' };
  }

  // unknown / missing kind
  return { error: 'unsupported_part' };
}

/**
 * Build the canonical descriptor for an artifact, or return an error marker if any
 * part is unsupported.
 */
export function buildDescriptor(
  artifact: { parts: A2APart[] }
): { parts: Record<string, unknown>[] } | ErrorResult {
  const parts = artifact?.parts;
  if (!Array.isArray(parts)) {
    return { error: 'unsupported_part' };
  }
  const descriptors: Record<string, unknown>[] = [];
  for (const part of parts) {
    const d = partToDescriptor(part);
    if ('error' in d) {
      return d as ErrorResult;
    }
    descriptors.push(d as Record<string, unknown>);
  }
  return { parts: descriptors };
}

export function a2aArtifactHash(input: A2AArtifactHashInput): A2AArtifactHashOutput | ErrorResult {
  const descriptor = buildDescriptor(input.artifact);
  if ('error' in descriptor) {
    return descriptor;
  }
  const canonical = jcsBytes(descriptor);
  return {
    outputs_hash: digestBytes(canonical),
    descriptor_hex: canonical.toString('hex'),
  };
}
