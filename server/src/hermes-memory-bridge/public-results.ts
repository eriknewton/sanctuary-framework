import { RECALL_MAX_PASSAGES, RECALL_PASSAGE_MAX_UNITS, RECALL_CREATED_AT_UNITS, RECALL_DATE_UNITS } from "./recall.js";
import { Buffer } from "node:buffer";

import { toolResult } from "../router.js";
import type { MemoryPassage, MemorySearchResult } from "../sdw/adapters/memory-backend.js";
import { memoryGetSuccessToolResult } from "../sdw/memory-tool-projection.js";
import {
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  MAX_REQUEST_ID_BYTES,
  MAX_RESULT_FRAME_BYTES,
} from "./constants.js";
import { HERMES_MEMORY_TOOL_NAMES, HERMES_MEMORY_WIRE_SCHEMAS, type HermesMemoryToolName } from "./envelopes.js";
import { parseStrictJsonObject } from "./strict-json.js";

export const HERMES_HELLO_PAYLOAD = Object.freeze({
  protocol_version: "2026-10-12",
  server_name: "sanctuary-hermes-memory-bridge",
});

const TOOL_CATALOG = Object.freeze({
    memory_insert: Object.freeze({
      input_schema: Object.freeze({
        type: "object",
        required: Object.freeze(["text", "taint"]),
        properties: Object.freeze({
          text: Object.freeze({ type: "string" }),
          taint: Object.freeze({
            type: "string",
            enum: Object.freeze(["user_content", "agent_derived_clean", "system_generated"]),
          }),
          tags: Object.freeze({ type: "array", items: Object.freeze({ type: "string" }) }),
          passage_id: Object.freeze({ type: "string" }),
        }),
      }),
    }),
    memory_get: Object.freeze({
      input_schema: Object.freeze({
        type: "object",
        required: Object.freeze(["passage_id"]),
        properties: Object.freeze({ passage_id: Object.freeze({ type: "string" }) }),
      }),
    }),
    memory_search: Object.freeze({
      input_schema: Object.freeze({
        type: "object",
        properties: Object.freeze({
          text: Object.freeze({ type: "string" }),
          query: Object.freeze({ type: "string" }),
          tag: Object.freeze({ type: "string" }),
          limit: Object.freeze({ type: "number" }),
        }),
      }),
    }),
    memory_recall: Object.freeze({ description: "Return a bounded context of matching saved passages.",
      input_schema: { type: "object", required: ["query"], properties: { query: { type: "string" } }, additionalProperties: false } }),
    sign_statement: Object.freeze({ description: "Not available yet; nothing is signed.",
      input_schema: { type: "object", required: ["statement"], properties: { statement: { type: "string" } }, additionalProperties: false } }),
    export_memory: Object.freeze({ description: "Not available yet; nothing is exported.",
      input_schema: { type: "object", required: ["scope"], properties: { scope: { type: "string", enum: ["all"] } }, additionalProperties: false } }),
    protection_rules: Object.freeze({ description: "Requests are refused.",
      input_schema: { type: "object", properties: {}, additionalProperties: false } }),
} satisfies Record<HermesMemoryToolName, object>);
export const HERMES_TOOLS_LIST_PAYLOAD = Object.freeze({
  tools: Object.freeze(HERMES_MEMORY_TOOL_NAMES.map(name => Object.freeze({ name, ...TOOL_CATALOG[name] }))),
});

// Must match the ordinary refusal outcomes in hermes-memory-relay/SEAM.md.
export const HERMES_TOOL_OUTCOMES = Object.freeze({
  denied: Object.freeze(toolResult({ outcome: "denied", message: "Request denied." })),
  unavailable_not_built: Object.freeze(toolResult({ outcome: "unavailable", message: "This is not available yet; nothing was done." })),
  unavailable: Object.freeze(toolResult({ outcome: "unavailable", message: "Sanctuary could not take this request right now; nothing was done." })),
  unconfirmed: Object.freeze(toolResult({ outcome: "unconfirmed", message: "I could not confirm whether this completed." })),
});
// Hermes counts a tool result containing these words as a failure, and three refusals must never look like three failures.
for (const result of Object.values(HERMES_TOOL_OUTCOMES)) {
  if (/error|failed/i.test(JSON.stringify(result))) throw new TypeError("Hermes outcome wording is invalid");
}
export type HermesToolOutcome = keyof typeof HERMES_TOOL_OUTCOMES;
export function buildToolOutcomeBytes(requestId: string, outcome: HermesToolOutcome): Uint8Array {
  return buildPublicResultFrameBytes(requestId, HERMES_TOOL_OUTCOMES[outcome]);
}

export const MAX_PUBLIC_RESULT_REQUEST_ID = "r".repeat(MAX_REQUEST_ID_BYTES);
// Must match the public `result { request_id, payload }` frame in hermes-memory-relay/SEAM.md.
export const PUBLIC_RESULT_ENVELOPE_MAX_BYTES =
  buildPublicResultFrameBytes(MAX_PUBLIC_RESULT_REQUEST_ID, {}).byteLength;

export type HermesPublicResultBuild =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly reason: string };

export function buildPublicResultFrameBytes(requestId: string, payload: Record<string, unknown>): Uint8Array {
  // Must match the public `result { request_id, payload }` frame in hermes-memory-relay/SEAM.md.
  return Buffer.from(JSON.stringify({ type: "result", request_id: requestId, payload }), "utf8");
}

export function buildPublicErrorFrameBytes(requestId: string, message: typeof HERMES_MEMORY_DENIAL | typeof HERMES_MEMORY_UNAVAILABLE): Uint8Array {
  // Must match the public `error { request_id, message }` frame in hermes-memory-relay/SEAM.md.
  return Buffer.from(JSON.stringify({ type: "error", request_id: requestId, message }), "utf8");
}

export function buildHelloResultBytes(requestId: string): HermesPublicResultBuild {
  return checkedResult(requestId, HERMES_HELLO_PAYLOAD);
}

export function buildToolsListResultBytes(requestId: string): HermesPublicResultBuild {
  return checkedResult(requestId, HERMES_TOOLS_LIST_PAYLOAD);
}

export function buildMemoryInsertSuccessBytes(
  requestId: string,
  ids: { readonly passageId: string; readonly documentId: string },
): HermesPublicResultBuild {
  return checkedResult(requestId, toolResult({
    outcome: "saved",
    inserted: true,
    passage: {
      passage_id: ids.passageId,
      document_id: ids.documentId,
    },
  }));
}

export function buildMemoryGetResultBytes(requestId: string, passage: MemoryPassage | null): HermesPublicResultBuild {
  if (passage === null) return { ok: true, bytes: buildToolOutcomeBytes(requestId, "denied") };
  if (!isExactMemoryPassage(passage)) return { ok: false, reason: "unexpected_passage_shape" };
  // Must match memoryGetSuccessToolResult in ../sdw/memory-tool-projection.ts.
  return checkedResult(requestId, memoryGetSuccessToolResult(passage));
}

export function buildMemorySearchResultBytes(
  requestId: string,
  results: readonly MemorySearchResult[],
): HermesPublicResultBuild {
  const projected: Record<string, unknown>[] = [];
  for (const result of results) {
    if (!isExactSearchResult(result) || !isExactMemoryPassage(result.passage)) {
      return { ok: false, reason: "unexpected_search_shape" };
    }
    projected.push({
      passage: publicPassageMetadata(result.passage),
      match_count: result.match_count,
    });
  }
  return checkedResult(requestId, toolResult({ results: projected }));
}

export function checkedResult(requestId: string, payload: Record<string, unknown>): HermesPublicResultBuild {
  const bytes = buildPublicResultFrameBytes(requestId, payload);
  if (bytes.byteLength > MAX_RESULT_FRAME_BYTES) return { ok: false, reason: "result_over_cap" };
  if (!isValidPublicFrame(bytes, "result", requestId)) return { ok: false, reason: "invalid_result_frame" };
  return { ok: true, bytes };
}

export function checkedError(requestId: string, message: typeof HERMES_MEMORY_DENIAL | typeof HERMES_MEMORY_UNAVAILABLE): Uint8Array {
  const bytes = buildPublicErrorFrameBytes(requestId, message);
  if (bytes.byteLength <= MAX_RESULT_FRAME_BYTES && isValidPublicFrame(bytes, "error", requestId)) return bytes;
  return buildPublicErrorFrameBytes(requestId, HERMES_MEMORY_DENIAL);
}

function isValidPublicFrame(bytes: Uint8Array, type: "result" | "error", requestId: string): boolean {
  let parsed: Record<string, unknown>;
  try {
    parsed = parseStrictJsonObject(bytes);
  } catch {
    return false;
  }
  if (parsed.type !== type || parsed.request_id !== requestId) return false;
  const schema = HERMES_MEMORY_WIRE_SCHEMAS.publicOutbound[type];
  const required = new Set(schema.required);
  const allowed = new Set([...schema.required, ...(schema.optional ?? [])]);
  const keys = Object.keys(parsed);
  if (keys.some((key) => !allowed.has(key))) return false;
  return [...required].every((key) => Object.prototype.hasOwnProperty.call(parsed, key));
}

function publicPassageMetadata(passage: MemoryPassage): Record<string, unknown> {
  return {
    passage_id: passage.passage_id,
    owner_ref: passage.owner_ref,
    content_hash: passage.content_hash,
    created_at: passage.created_at,
    chunk_count: passage.chunk_count,
    tag_count: passage.tags.length,
  };
}

function isExactSearchResult(result: MemorySearchResult): boolean {
  return exactKeys(result as unknown as Record<string, unknown>, ["passage", "match_count"]) &&
    Number.isSafeInteger(result.match_count) &&
    result.match_count >= 0;
}

function isExactMemoryPassage(passage: MemoryPassage): boolean {
  return exactKeys(passage as unknown as Record<string, unknown>, [
    "passage_id",
    "owner_ref",
    "text",
    "tags",
    "metadata",
    "created_at",
    "chunk_count",
    "content_hash",
    "provenance_status",
  ]) &&
    typeof passage.passage_id === "string" &&
    typeof passage.owner_ref === "string" &&
    typeof passage.text === "string" &&
    Array.isArray(passage.tags) &&
    Array.isArray(passage.metadata) &&
    typeof passage.created_at === "string" &&
    Number.isSafeInteger(passage.chunk_count) &&
    typeof passage.content_hash === "string" &&
    (passage.provenance_status === "verified" || passage.provenance_status === "unsigned");
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

/** Encode only the bounded canonical projection, never full passage objects. */
export function buildMemoryRecallResultBytes(requestId: string, result: import("./recall.js").HermesRecallResult): HermesPublicResultBuild {
  return checkedResult(requestId, toolResult(result));
}

// SDW identifier grammar permits at most 256 ASCII units, with no JSON escapes.
// Must match SDW_IDENTIFIER_PATTERN in server/src/sdw/grammar.ts; this round permits the bridge-side pin only.
export const HERMES_RESULT_IDENTIFIER_MAX_UNITS = 256;
// A control unit is six inner JSON characters; the outer frame escapes its backslash once more.
// Three UTF-8 bytes per unescaped BMP unit is smaller, so seven bounds both cases.
export const HERMES_RESULT_TEXT_BYTES_PER_UNIT = 7;
const maximumIdentifier = "p".repeat(HERMES_RESULT_IDENTIFIER_MAX_UNITS);
const canonicalTimestamp = "2000-01-01T00:00:00.000Z";
if (canonicalTimestamp.length !== RECALL_CREATED_AT_UNITS) throw new TypeError("Recall timestamp derivation mismatch");
const recallSkeleton = { outcome: "recalled", context: Array.from({ length: RECALL_MAX_PASSAGES },
  () => `- (saved ${canonicalTimestamp.slice(0, RECALL_DATE_UNITS)}) \n`).join(""),
  passages: Array.from({ length: RECALL_MAX_PASSAGES }, () => ({ passage_id: maximumIdentifier, created_at: canonicalTimestamp })),
  truncated: false };
const fixedMaximum = Math.max(...Object.values(HERMES_TOOL_OUTCOMES).map(result =>
  buildPublicResultFrameBytes(MAX_PUBLIC_RESULT_REQUEST_ID, result).byteLength));
const insertMaximum = buildMemoryInsertSuccessBytes(MAX_PUBLIC_RESULT_REQUEST_ID,
  { passageId: maximumIdentifier, documentId: maximumIdentifier });
if (!insertMaximum.ok) throw new TypeError("Insert result derivation mismatch");
/**
 * Maximum serialized result bytes, including toolResult's two-space indentation and outer JSON encoding.
 * Get is capped at insert and read. Search emits the unbounded stored created_at unchanged,
 * so its bound is enforced by checkedResult's fixed refusal, not a metadata size derivation.
 */
export const HERMES_RESULT_MAX_BYTES_BY_KIND = Object.freeze({
  hello: buildPublicResultFrameBytes(MAX_PUBLIC_RESULT_REQUEST_ID, HERMES_HELLO_PAYLOAD).byteLength,
  tools_list: buildPublicResultFrameBytes(MAX_PUBLIC_RESULT_REQUEST_ID, HERMES_TOOLS_LIST_PAYLOAD).byteLength,
  memory_insert: Math.max(fixedMaximum, insertMaximum.bytes.byteLength),
  memory_get: MAX_RESULT_FRAME_BYTES,
  memory_search: MAX_RESULT_FRAME_BYTES,
  memory_recall: Math.max(fixedMaximum, buildPublicResultFrameBytes(MAX_PUBLIC_RESULT_REQUEST_ID, toolResult(recallSkeleton)).byteLength +
    RECALL_MAX_PASSAGES * RECALL_PASSAGE_MAX_UNITS * HERMES_RESULT_TEXT_BYTES_PER_UNIT),
  sign_statement: fixedMaximum,
  export_memory: fixedMaximum,
  protection_rules: fixedMaximum,
} satisfies Record<HermesMemoryToolName | "hello" | "tools_list", number>);
export const HERMES_MAX_VALID_RESULT_FRAME_BYTES = Math.max(...Object.values(HERMES_RESULT_MAX_BYTES_BY_KIND));
if (HERMES_MAX_VALID_RESULT_FRAME_BYTES > MAX_RESULT_FRAME_BYTES) throw new RangeError("Hermes result exceeds relay frame cap");
