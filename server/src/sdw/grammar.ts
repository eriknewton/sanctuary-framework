import { stringToBytes, toBase64url } from "../core/encoding.js";
import { hash } from "../core/hashing.js";
import { SdwValidationError } from "./errors.js";

export const SDW_IDENTIFIER_PATTERN = /^[A-Za-z0-9._:@+-]{1,256}$/;
export const QUERY_SEQUENCE_KEY_WIDTH = 20;
const QUERY_SEQUENCE_KEY_PATTERN = /^\d{20}$/;

export function assertSdwIdentifier(value: string, label: string): string {
  if (!isSdwIdentifier(value)) {
    throw new SdwValidationError(
      "invalid_identifier",
      `Invalid SDW identifier: ${label}`,
    );
  }
  return value;
}

export function isSdwIdentifier(value: string): boolean {
  if (!SDW_IDENTIFIER_PATTERN.test(value)) return false;
  return !hasUnpairedSurrogate(value);
}

export function sdwAad(
  fortressId: string,
  namespace: string,
  key: string,
): Uint8Array {
  return lengthPrefixedUtf8([
    assertSdwIdentifier(fortressId, "fortress_id"),
    assertSdwIdentifier(namespace, "namespace"),
    assertSdwIdentifier(key, "key"),
  ]);
}

export function lengthPrefixedUtf8(components: readonly string[]): Uint8Array {
  const chunks = components.map((component) => {
    const bytes = stringToBytes(component);
    return stringToBytes(`${bytes.length}:` + component);
  });
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function sdwAadDebugString(
  fortressId: string,
  namespace: string,
  key: string,
): string {
  return `${stringToBytes(fortressId).length}:${fortressId}` +
    `${stringToBytes(namespace).length}:${namespace}` +
    `${stringToBytes(key).length}:${key}`;
}

export function deriveSourceRefId(source: SdwSourceRefInput): string {
  const domain = stringToBytes("sdw-source-ref-v1");
  const body = stringToBytes(canonicalJson(source));
  const bytes = new Uint8Array(domain.length + body.length);
  bytes.set(domain, 0);
  bytes.set(body, domain.length);
  return toBase64url(hash(bytes)).replace(/_/g, ".");
}

export interface SdwSourceRefInput {
  readonly kind: "file" | "url" | "paste" | "tool_output" | "internal";
  readonly uri?: string;
  readonly title?: string;
  readonly media_type?: string;
}

export function catalogKey(): "catalog.environment" {
  return "catalog.environment";
}

export function stateKey(scope: string, stateId: string): string {
  assertSdwIdentifier(scope, "scope");
  assertSdwIdentifier(stateId, "state_id");
  return `state.${scope}.${stateId}`;
}

export function queryKey(paddedSequence: string, queryId: string): string {
  assertQueryKeySequence(paddedSequence);
  assertSdwIdentifier(queryId, "query_id");
  return `query.${paddedSequence}.${queryId}`;
}

export function padQuerySequence(sequence: number): string {
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new SdwValidationError("invalid_identifier", "Invalid SDW identifier: query_sequence");
  }
  const padded = String(sequence).padStart(QUERY_SEQUENCE_KEY_WIDTH, "0");
  assertQueryKeySequence(padded);
  return padded;
}

function assertQueryKeySequence(paddedSequence: string): string {
  if (!QUERY_SEQUENCE_KEY_PATTERN.test(paddedSequence)) {
    throw new SdwValidationError("invalid_identifier", "Invalid SDW identifier: query_sequence");
  }
  return assertSdwIdentifier(paddedSequence, "query_sequence");
}

export function documentKey(documentId: string): string {
  assertSdwIdentifier(documentId, "document_id");
  return `doc.${documentId}`;
}

/** Frozen Slice-C companion key: one encrypted record beside each document. */
export function documentProvenanceKey(documentId: string): string {
  assertSdwIdentifier(documentId, "document_id");
  return `prov.${documentId}`;
}

/** Replace-in-place quarantine status; never an attacker-growable event log. */
export function documentProvenanceStatusKey(documentId: string): string {
  assertSdwIdentifier(documentId, "document_id");
  return `prov-status.${documentId}`;
}

export function documentChunkKey(
  documentId: string,
  chunkOrdinalPadded: string,
  chunkId: string,
): string {
  assertSdwIdentifier(documentId, "document_id");
  assertSdwIdentifier(chunkOrdinalPadded, "chunk_ordinal");
  assertSdwIdentifier(chunkId, "chunk_id");
  return `chunk.${documentId}.${chunkOrdinalPadded}.${chunkId}`;
}

export function vectorKey(vectorId: string): string {
  assertSdwIdentifier(vectorId, "vector_id");
  return `vec.${vectorId}`;
}

export function vectorMapKey(segmentId: string, label: number): string {
  assertSdwIdentifier(segmentId, "segment_id");
  if (!Number.isSafeInteger(label) || label < 0) {
    throw new SdwValidationError("invalid_identifier", "Invalid SDW identifier: hnsw_label");
  }
  return `map.${segmentId}.${label}`;
}

export function vectorSegmentKey(segmentId: string, generation: number): string {
  assertSdwIdentifier(segmentId, "segment_id");
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new SdwValidationError("invalid_identifier", "Invalid SDW identifier: generation");
  }
  return `segment.${segmentId}.${generation}`;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) return true;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  const input = value as { readonly [key: string]: unknown };
  const output: { [key: string]: unknown } = {};
  for (const key of Object.keys(input).sort()) {
    const item = input[key];
    if (item !== undefined) output[key] = canonicalize(item);
  }
  return output;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}
