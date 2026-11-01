// Real encoders preserve result and stdio frame bounds, including canonical timestamp projection.
import { expect, it } from "vitest";
import { buildMemoryRecallResultBytes, buildMemorySearchResultBytes, buildToolOutcomeBytes,
  HERMES_RESULT_MAX_BYTES_BY_KIND, HERMES_RESULT_IDENTIFIER_MAX_UNITS, HERMES_TOOL_OUTCOMES, MAX_PUBLIC_RESULT_REQUEST_ID } from "../../src/hermes-memory-bridge/public-results.js";
import { HermesBridgeCore } from "../../src/hermes-memory-bridge/bridge-core.js";
import { parsePublicFrame, type NodeToRelayInput } from "../../src/hermes-memory-bridge/envelopes.js";
import { shouldUseDenial } from "../../src/hermes-memory-bridge/envelopes.js";
import { MAX_RESULT_FRAME_BYTES } from "../../src/hermes-memory-bridge/constants.js";
import { RECALL_PASSAGE_MAX_UNITS, RECALL_MAX_PASSAGES, RECALL_CONTEXT_MAX_UNITS, HermesRecallBudget } from "../../src/hermes-memory-bridge/recall.js";
import { validateCallResult, resultLine, MAX_STDIO_LINE_BYTES } from "../../src/hermes-memory-client/protocol.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { TestSdwMemoryBackendAdapter } from "../sdw/test-memory-backend.js";
import { SdwDocumentCorpusStore } from "../../src/sdw/document-corpus-store.js";

function verify(bytes: Uint8Array, kind: "memory_recall" | "memory_search") {
  expect(bytes.byteLength).toBeLessThanOrEqual(HERMES_RESULT_MAX_BYTES_BY_KIND[kind]);
  expect(bytes.byteLength).toBeLessThanOrEqual(MAX_RESULT_FRAME_BYTES);
  expect(shouldUseDenial(MAX_PUBLIC_RESULT_REQUEST_ID, bytes)).toBe(false);
  const payload = Buffer.from(JSON.stringify(JSON.parse(Buffer.from(bytes).toString()).payload));
  validateCallResult(payload);
  expect(resultLine(MAX_PUBLIC_RESULT_REQUEST_ID, payload).byteLength).toBeLessThanOrEqual(MAX_STDIO_LINE_BYTES);
}
it("bounds the maximum recall escape vector with seven bytes per unit", () => {
  const excerpt = "\u0001".repeat(RECALL_PASSAGE_MAX_UNITS - 1) + '"';
  const passages = Array.from({ length: RECALL_MAX_PASSAGES }, () => ({ passage_id: "p".repeat(HERMES_RESULT_IDENTIFIER_MAX_UNITS), created_at: "2026-01-01T00:00:00.000Z" }));
  const result = buildMemoryRecallResultBytes(MAX_PUBLIC_RESULT_REQUEST_ID, { outcome: "recalled", passages,
    context: passages.map(() => `- (saved 2026-01-01) ${excerpt}\n`).join(""), truncated: false });
  expect(result.ok).toBe(true);
  if (result.ok) verify(result.bytes, "memory_recall");
});
it("keeps every fixed outcome ordinary and free of failure words", () => {
  for (const kind of Object.keys(HERMES_TOOL_OUTCOMES) as (keyof typeof HERMES_TOOL_OUTCOMES)[]) {
    const bytes = buildToolOutcomeBytes(MAX_PUBLIC_RESULT_REQUEST_ID, kind);
    expect(Buffer.from(bytes).toString()).not.toMatch(/error|failed/i);
    expect(JSON.parse(Buffer.from(bytes).toString()).type).toBe("result");
  }
});
it("bounds search at limit twenty while recall projects long stored timestamps", async () => {
  const storage = new MemoryStorage();
  const options = { storage, masterKey: new Uint8Array(32).fill(17), fortressId: "recall-frame", ownerRef: "agent" };
  const adapter = new TestSdwMemoryBackendAdapter(options);
  const corpus = new SdwDocumentCorpusStore(options);
  // Whitespace extends a parseable stored timestamp beyond one public frame while preserving the instant.
  const storedTime = "January 1, 2026 " + " ".repeat(MAX_RESULT_FRAME_BYTES / 2);
  for (const passage_id of ["a", "b", "c", "extended"]) {
    await adapter.insertPassage({ passage_id, text: "board meeting" }, "user_content");
    const document = await corpus.getDocument(`mem.agent.${passage_id}`);
    await corpus.putDocument({ ...document!, created_at: passage_id === "extended" ? "+010000-01-01T00:00:00.000Z" : storedTime }, "user_content");
  }
  const searched = buildMemorySearchResultBytes(MAX_PUBLIC_RESULT_REQUEST_ID, await adapter.searchPassages({ text: "board", limit: 20 }));
  expect(searched).toEqual({ ok: false, reason: "result_over_cap" });
  const run = async (name: "memory_search" | "memory_recall", args: Record<string, unknown>) => {
    let deliver!: (frame: Extract<NodeToRelayInput, { type: "response" }>) => void;
    const response = new Promise<Extract<NodeToRelayInput, { type: "response" }>>(resolve => { deliver = resolve; });
    const core = new HermesBridgeCore({ agentId: "agent", adapter, appendAudit: async () => undefined,
      writeFrame: frame => { if (frame.type === "response") deliver(frame); }, nowMs: () => 0,
      setTimer: () => ({}), clearTimer() {}, abort: new AbortController() });
    try {
      core.relayFrame({ kind: "accepted", connectionId: "c1" });
      const publicBytes = Buffer.from(JSON.stringify({ type: "tools_call", request_id: MAX_PUBLIC_RESULT_REQUEST_ID, name, arguments: args }));
      core.relayFrame({ kind: "frame", connectionId: "c1", publicBytes, publicFrame: parsePublicFrame(publicBytes) });
      return (await response).publicPayloadBytes;
    } finally { core.relayEof(); }
  };
  const searchBytes = await run("memory_search", { text: "board", limit: 20 });
  expect(searchBytes).toEqual(buildToolOutcomeBytes(MAX_PUBLIC_RESULT_REQUEST_ID, "denied"));
  verify(searchBytes, "memory_search");
  const recallBytes = await run("memory_recall", { query: "board meeting" });
  const recallBody = JSON.parse(JSON.parse(Buffer.from(recallBytes).toString()).payload.content[0].text);
  expect(recallBody.outcome).toBe("recalled");
  expect(recallBody.passages).toHaveLength(RECALL_MAX_PASSAGES);
  expect(recallBody.passages.every((p: { created_at: string }) => p.created_at.length === 24)).toBe(true);
  verify(recallBytes, "memory_recall");
  const recalled = await adapter.recallPassages(new HermesRecallBudget("board meeting", () => 0, new AbortController().signal));
  expect(recalled.passages).toHaveLength(3);
  expect(recalled.passages.every(p => p.created_at.length === 24)).toBe(true);
  expect(recalled.passages.some(p => p.passage_id === "extended")).toBe(false);
  expect(recalled.context.length).toBeLessThanOrEqual(RECALL_CONTEXT_MAX_UNITS);
  const encoded = buildMemoryRecallResultBytes(MAX_PUBLIC_RESULT_REQUEST_ID, recalled);
  expect(encoded.ok).toBe(true);
  if (encoded.ok) verify(encoded.bytes, "memory_recall");
});

it("passes a full twenty-result search vector through relay and shim encoders", () => {
  const results = Array.from({ length: 20 }, () => ({ match_count: 1, passage: {
    passage_id: "p".repeat(HERMES_RESULT_IDENTIFIER_MAX_UNITS), owner_ref: "a".repeat(HERMES_RESULT_IDENTIFIER_MAX_UNITS),
    text: "matching text", tags: [], metadata: [], created_at: "2026-01-01T00:00:00.000Z", chunk_count: 1,
    content_hash: "h".repeat(43), provenance_status: "verified" as const, // 43 units encode a SHA-256 digest as unpadded base64url.
  } }));
  const encoded = buildMemorySearchResultBytes(MAX_PUBLIC_RESULT_REQUEST_ID, results);
  expect(encoded.ok).toBe(true);
  if (encoded.ok) verify(encoded.bytes, "memory_search");
});
