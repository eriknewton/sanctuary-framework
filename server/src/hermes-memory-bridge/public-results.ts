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
import { HERMES_MEMORY_WIRE_SCHEMAS } from "./envelopes.js";
import { parseStrictJsonObject } from "./strict-json.js";

export const HERMES_HELLO_PAYLOAD = Object.freeze({
  protocol_version: "2026-10-12",
  server_name: "sanctuary-hermes-memory-bridge",
});

export const HERMES_TOOLS_LIST_PAYLOAD = Object.freeze({
  tools: Object.freeze([
    Object.freeze({
      name: "memory_insert",
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
    Object.freeze({
      name: "memory_get",
      input_schema: Object.freeze({
        type: "object",
        required: Object.freeze(["passage_id"]),
        properties: Object.freeze({ passage_id: Object.freeze({ type: "string" }) }),
      }),
    }),
    Object.freeze({
      name: "memory_search",
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
  ]),
});

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
    inserted: true,
    passage: {
      passage_id: ids.passageId,
      document_id: ids.documentId,
    },
  }));
}

export function buildMemoryGetResultBytes(requestId: string, passage: MemoryPassage | null): HermesPublicResultBuild {
  if (passage === null) return checkedResult(requestId, toolResult({ found: false }));
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

function checkedResult(requestId: string, payload: Record<string, unknown>): HermesPublicResultBuild {
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
