import { toolResult } from "../router.js";
import type { MemoryPassage } from "./adapters/memory-backend.js";

/** Full body view, reserved for explicit single-passage retrieval. */
export function publicFullPassage(passage: MemoryPassage): Record<string, unknown> {
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

export function memoryGetSuccessToolResult(passage: MemoryPassage): {
  content: Array<{ type: "text"; text: string }>;
} {
  return toolResult({ found: true, passage: publicFullPassage(passage) });
}

export function memoryGetSuccessFrameUtf8Bytes(passage: MemoryPassage): number {
  // The bridge cap must measure the same JSON envelope that memory_get emits,
  // so the commit check and MCP tool share this encoder rather than mirror it.
  return Buffer.byteLength(JSON.stringify(memoryGetSuccessToolResult(passage)), "utf8");
}
