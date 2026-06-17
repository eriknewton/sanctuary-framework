/**
 * SDW memory MCP tool surface: `memory_insert` / `memory_get` /
 * `memory_search` / `memory_list` / `memory_delete` / `memory_count`.
 *
 * These expose the SHIPPED `MemoryBackendAdapter` (PR #484) over MCP so a
 * fleet agent can reach its sovereign passages - today the only registered
 * SDW tools are `sdw_export` / `sdw_import` / `sdw_export_delete`, so no agent
 * can read or write passages over MCP at all.
 *
 * HONEST PRIMITIVE (Crux 3 - never overclaim): this is a SOVEREIGN PASSAGE
 * STORE with custody + audit + egress, NOT a "brain-agnostic memory interface
 * with lossless cross-brain interchange." The shape is flat text + tags +
 * content_hash (a Letta archival-passage shape), with no embeddings, no graph,
 * no entities, and no in-place mutation (insert + delete only). The tool
 * descriptions name it as exactly that, so an agent reading them is not misled.
 * Vector / semantic retrieval IQ stays in a swappable engine behind this same
 * contract (composable sovereignty: the engine is a CEILING pick, the custody
 * floor is fixed).
 *
 * CUSTODY INHERITANCE (Crux 7): every `memory_insert` routes through the
 * adapter's `insertPassage` -> `mintPersistable` -> `classifyRecord`, so the
 * SDW write-gate gates secrets out structurally BEFORE encryption. Nothing
 * here bypasses the gate.
 *
 * TIER DISCIPLINE (MUST-NEVER #3): `memory_delete` is a secure-overwrite,
 * irreversible, and is therefore a Tier-1 `write` tool - the approval gate
 * fires before deletion, same posture as the existing SDW delete path. Reads
 * (`memory_get` / `memory_search` / `memory_list` / `memory_count`) are
 * `read` tools.
 *
 * DENIAL DISCIPLINE (MUST-NEVER #5, #7): any failure returns the fixed-denial
 * schema (no policy detail, no record bodies, no key material leaks); details
 * go to the audit log only. No silent degrade.
 */

import { randomBytes } from "node:crypto";
import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import { fixedDenial } from "../agent-native/safety-base.js";
import { toBase64url } from "../core/encoding.js";
import type { PersistableTaint } from "./provenance.js";
import type {
  MemoryBackendAdapter,
  MemoryPassage,
  MemorySearchResult,
} from "./adapters/memory-backend.js";
import { SdwValidationError } from "./errors.js";
import { isSdwIdentifier } from "./grammar.js";

const MAX_TEXT_BYTES = 1024 * 1024;
const PERSISTABLE_TAINTS: readonly PersistableTaint[] = [
  "user_content",
  "agent_derived_clean",
  "system_generated",
];

export interface SdwMemoryToolsOptions {
  /** The shipped sovereign passage backend, already scoped to one owner_ref. */
  readonly adapter: MemoryBackendAdapter;
  readonly auditLog: AuditLog;
}

/** Public, brain-agnostic view of a passage (the shipped shape, named honestly). */
function publicPassage(passage: MemoryPassage): Record<string, unknown> {
  return {
    passage_id: passage.passage_id,
    owner_ref: passage.owner_ref,
    text: passage.text,
    tags: [...passage.tags],
    metadata: passage.metadata.map((entry) => ({ ...entry })),
    created_at: passage.created_at,
    chunk_count: passage.chunk_count,
    content_hash: passage.content_hash,
  };
}

function publicSearchResult(result: MemorySearchResult): Record<string, unknown> {
  return {
    passage: publicPassage(result.passage),
    match_count: result.match_count,
  };
}

function asTaint(value: unknown): PersistableTaint | null {
  return typeof value === "string" &&
    (PERSISTABLE_TAINTS as readonly string[]).includes(value)
    ? (value as PersistableTaint)
    : null;
}

function asStringArray(value: unknown): string[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    return null;
  }
  return value as string[];
}

function asPositiveInt(value: unknown): number | null {
  if (value === undefined) return null; // caller default
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? value
    : Number.NaN; // sentinel for "present but invalid"
}

function generateMemoryPassageId(): string {
  return toBase64url(new Uint8Array(randomBytes(15)));
}

export function createSdwMemoryTools(options: SdwMemoryToolsOptions): ToolDefinition[] {
  const { adapter, auditLog } = options;

  const auditFailure = (operation: string, details: Record<string, unknown>): Promise<void> =>
    auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "system",
      result: "failure",
      details,
    });

  const auditSuccess = (operation: string, details: Record<string, unknown>): Promise<void> =>
    auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "principal",
      result: "success",
      details,
    });

  const deny = (operation: string) =>
    toolResult(fixedDenial(`audit:${operation}`, "request_review", null));

  // -- memory_insert (write - inherits the SDW secret write-gate) --------------
  const memoryInsert: ToolDefinition = {
    name: "memory_insert",
    description:
      "Store a text passage in your sovereign memory vault (SDW). Encrypted at " +
      "rest under your operator keys, secret-gated at write time, and audited. " +
      "This is a passage store: flat text plus tags, with no in-place edit " +
      "(insert and delete only). Retrieval IQ (embeddings, ranking) stays in a " +
      "swappable engine; this is the sovereign custody layer underneath it.",
    tool_class: "write",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Passage text to store" },
        taint: {
          type: "string",
          enum: [...PERSISTABLE_TAINTS],
          description:
            "Provenance of the text: user_content (conversation-derived), " +
            "agent_derived_clean (agent summary), or system_generated. " +
            "This is a hint, not a secret-free guarantee: forbidden taints " +
            "and secret-classifier hits are rejected before encryption.",
        },
        tags: {
          type: "array",
          items: { type: "string" },
          description: "Optional tags (SDW identifier grammar)",
        },
        passage_id: {
          type: "string",
          description: "Optional caller-supplied id (SDW identifier grammar); generated if absent",
        },
      },
      required: ["text", "taint"],
    },
    handler: async (args) => {
      const text = args.text;
      const taint = asTaint(args.taint);
      const tags = asStringArray(args.tags);
      if (typeof text !== "string" || text.length === 0) {
        await auditFailure("memory_insert_denied", { denial_class: "invalid_text" });
        return deny("memory_insert");
      }
      if (Buffer.byteLength(text, "utf8") > MAX_TEXT_BYTES) {
        await auditFailure("memory_insert_denied", { denial_class: "text_too_large" });
        return deny("memory_insert");
      }
      if (taint === null) {
        await auditFailure("memory_insert_denied", { denial_class: "invalid_taint" });
        return deny("memory_insert");
      }
      if (tags === null) {
        await auditFailure("memory_insert_denied", { denial_class: "invalid_tags" });
        return deny("memory_insert");
      }
      const passageId = args.passage_id;
      if (passageId !== undefined && typeof passageId !== "string") {
        await auditFailure("memory_insert_denied", { denial_class: "invalid_passage_id" });
        return deny("memory_insert");
      }
      if (typeof passageId === "string" && !isSdwIdentifier(passageId)) {
        await auditFailure("memory_insert_denied", { denial_class: "invalid_passage_id" });
        return deny("memory_insert");
      }
      const auditedPassageId = passageId ?? generateMemoryPassageId();
      try {
        await auditSuccess("memory_insert_intent", {
          phase: "intent",
          passage_id: auditedPassageId,
          text_bytes: Buffer.byteLength(text, "utf8"),
          tag_count: tags.length,
        });
      } catch {
        return deny("memory_insert");
      }
      let passage: MemoryPassage;
      try {
        passage = await adapter.insertPassage(
          { text, tags, passage_id: auditedPassageId },
          taint,
        );
      } catch (error) {
        // SdwValidationError (e.g. classifier_reject, duplicate_passage,
        // invalid identifier) -> fixed denial; category to audit only.
        const category = error instanceof SdwValidationError ? error.category : "insert_failed";
        await auditFailure("memory_insert_denied", {
          phase: "outcome",
          denial_class: category,
          passage_id: auditedPassageId,
        });
        return deny("memory_insert");
      }
      await auditSuccess("memory_insert", {
        phase: "outcome",
        passage_id: passage.passage_id,
        owner_ref: passage.owner_ref,
        content_hash: passage.content_hash,
        chunk_count: passage.chunk_count,
      });
      return toolResult({ inserted: true, passage: publicPassage(passage) });
    },
  };

  // -- memory_get (read) -------------------------------------------------------
  const memoryGet: ToolDefinition = {
    name: "memory_get",
    description:
      "Fetch one passage from your sovereign memory vault by id. Decrypts on read " +
      "and verifies the content hash (fails closed on any integrity mismatch).",
    tool_class: "read",
    inputSchema: {
      type: "object",
      properties: {
        passage_id: { type: "string", description: "Passage id to fetch" },
      },
      required: ["passage_id"],
    },
    handler: async (args) => {
      const passageId = args.passage_id;
      if (typeof passageId !== "string" || passageId.length === 0) {
        await auditFailure("memory_get_denied", { denial_class: "invalid_passage_id" });
        return deny("memory_get");
      }
      try {
        const passage = await adapter.getPassage(passageId);
        if (passage === null) {
          await auditSuccess("memory_get", { passage_id: passageId, result_count: 0 });
          return toolResult({ found: false });
        }
        await auditSuccess("memory_get", { passage_id: passageId, result_count: 1 });
        return toolResult({ found: true, passage: publicPassage(passage) });
      } catch (error) {
        const category = error instanceof SdwValidationError ? error.category : "get_failed";
        await auditFailure("memory_get_denied", { denial_class: category });
        return deny("memory_get");
      }
    },
  };

  // -- memory_search (read - deterministic lexical, no embeddings) --------------
  const memorySearch: ToolDefinition = {
    name: "memory_search",
    description:
      "Deterministic substring search over your sovereign memory passages. This is " +
      "the always-available lexical search so you can query your own vault with no " +
      "engine running; semantic / embedding search lives in a swappable engine, not here.",
    tool_class: "read",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Case-insensitive substring to match" },
        tag: { type: "string", description: "Optional: restrict to passages carrying this tag" },
        limit: { type: "number", description: "Optional max results" },
      },
      required: ["text"],
    },
    handler: async (args) => {
      const text = args.text;
      const tag = args.tag;
      const limit = asPositiveInt(args.limit);
      if (typeof text !== "string") {
        await auditFailure("memory_search_denied", { denial_class: "invalid_text" });
        return deny("memory_search");
      }
      if (tag !== undefined && typeof tag !== "string") {
        await auditFailure("memory_search_denied", { denial_class: "invalid_tag" });
        return deny("memory_search");
      }
      if (Number.isNaN(limit)) {
        await auditFailure("memory_search_denied", { denial_class: "invalid_limit" });
        return deny("memory_search");
      }
      try {
        const results = await adapter.searchPassages({
          text,
          tag: typeof tag === "string" ? tag : undefined,
          limit: limit ?? undefined,
        });
        await auditSuccess("memory_search", {
          result_count: results.length,
          limited: limit ?? null,
          tag_filter: typeof tag === "string",
        });
        return toolResult({ results: results.map(publicSearchResult) });
      } catch (error) {
        const category = error instanceof SdwValidationError ? error.category : "search_failed";
        await auditFailure("memory_search_denied", { denial_class: category });
        return deny("memory_search");
      }
    },
  };

  // -- memory_list (read - stable key order, cursor pagination) -----------------
  const memoryList: ToolDefinition = {
    name: "memory_list",
    description:
      "List passages in your sovereign memory vault in stable id order, with optional " +
      "cursor pagination (pass the last seen passage_id as `after`).",
    tool_class: "read",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Optional max results" },
        after: { type: "string", description: "Optional cursor: return ids strictly after this one" },
      },
    },
    handler: async (args) => {
      const limit = asPositiveInt(args.limit);
      const after = args.after;
      if (Number.isNaN(limit)) {
        await auditFailure("memory_list_denied", { denial_class: "invalid_limit" });
        return deny("memory_list");
      }
      if (after !== undefined && typeof after !== "string") {
        await auditFailure("memory_list_denied", { denial_class: "invalid_after" });
        return deny("memory_list");
      }
      try {
        const passages = await adapter.listPassages({
          limit: limit ?? undefined,
          after: typeof after === "string" ? after : undefined,
        });
        await auditSuccess("memory_list", {
          result_count: passages.length,
          limited: limit ?? null,
          after_provided: typeof after === "string",
        });
        return toolResult({ passages: passages.map(publicPassage) });
      } catch (error) {
        const category = error instanceof SdwValidationError ? error.category : "list_failed";
        await auditFailure("memory_list_denied", { denial_class: category });
        return deny("memory_list");
      }
    },
  };

  // -- memory_count (read) ------------------------------------------------------
  const memoryCount: ToolDefinition = {
    name: "memory_count",
    description: "Count the passages in your sovereign memory vault (this owner scope).",
    tool_class: "read",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      try {
        const count = await adapter.countPassages();
        await auditSuccess("memory_count", { count });
        return toolResult({ count });
      } catch (error) {
        const category = error instanceof SdwValidationError ? error.category : "count_failed";
        await auditFailure("memory_count_denied", { denial_class: category });
        return deny("memory_count");
      }
    },
  };

  // -- memory_delete (write - Tier-1, irreversible secure-overwrite) ------------
  const memoryDelete: ToolDefinition = {
    name: "memory_delete",
    description:
      "Permanently delete a passage from your sovereign memory vault (secure " +
      "overwrite where the storage backend supports it; a plain delete otherwise). " +
      "Tier 1: irreversible, so it requires operator approval " +
      "before execution and fails closed.",
    tool_class: "write",
    inputSchema: {
      type: "object",
      properties: {
        passage_id: { type: "string", description: "Passage id to delete" },
      },
      required: ["passage_id"],
    },
    handler: async (args) => {
      const passageId = args.passage_id;
      if (typeof passageId !== "string" || passageId.length === 0) {
        await auditFailure("memory_delete_denied", { denial_class: "invalid_passage_id" });
        return deny("memory_delete");
      }
      try {
        await auditSuccess("memory_delete_intent", { phase: "intent", passage_id: passageId });
      } catch {
        return deny("memory_delete");
      }
      let deleted: boolean;
      try {
        deleted = await adapter.deletePassage(passageId);
      } catch (error) {
        const category = error instanceof SdwValidationError ? error.category : "delete_failed";
        await auditFailure("memory_delete_denied", {
          phase: "outcome",
          denial_class: category,
          passage_id: passageId,
        });
        return deny("memory_delete");
      }
      if (!deleted) {
        await auditFailure("memory_delete_denied", {
          phase: "outcome",
          denial_class: "not_found",
          passage_id: passageId,
        });
        return toolResult({ deleted: false, found: false });
      }
      await auditSuccess("memory_delete", { phase: "outcome", passage_id: passageId });
      return toolResult({ deleted: true });
    },
  };

  return [
    memoryInsert,
    memoryGet,
    memorySearch,
    memoryList,
    memoryCount,
    memoryDelete,
  ];
}
