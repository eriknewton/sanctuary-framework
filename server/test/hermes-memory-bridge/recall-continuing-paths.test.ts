// Recall uses the production encrypted adapter and preserves trust checks through the bridge.
import { expect, it } from "vitest";
import { HermesBridgeCore, type HermesBridgeAuditRecord } from "../../src/hermes-memory-bridge/bridge-core.js";
import { parsePublicFrame, type NodeToRelayInput } from "../../src/hermes-memory-bridge/envelopes.js";
import { RECALL_WALL_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { SdwDocumentCorpusStore, padChunkOrdinal } from "../../src/sdw/document-corpus-store.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { documentProvenanceKey } from "../../src/sdw/grammar.js";
import { passageContentHash } from "../../src/sdw/write-gate.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { TestSdwMemoryBackendAdapter } from "../sdw/test-memory-backend.js";

const CREATED = "2026-11-01T00:00:00.000Z";
const MATCH = { outcome: "recalled", context: "- (saved 2026-11-01) board meeting\n",
  passages: [{ passage_id: "a", created_at: CREATED }], truncated: false };
async function drainUntil(condition: () => boolean) {
  // One thousand microtask turns bound this in-memory harness; no wall-clock sleeps or stalled I/O.
  for (let turn = 0; turn < 1000 && !condition(); turn++) await Promise.resolve();
  expect(condition()).toBe(true);
}
async function fixture() {
  const storage = new MemoryStorage(), masterKey = new Uint8Array(32).fill(17), fortressId = "recall-paths";
  let complete = false, now = 0, rejectAudit = false;
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey, fortressId, ownerRef: "agent", now: () => CREATED,
    resolveMemoryIntegrityState: async () => complete ? "state_COMPLETE" : "state_PRE_MIGRATION" });
  await adapter.insertPassage({ passage_id: "a", text: "board meeting" }, "user_content");
  const corpus = new SdwDocumentCorpusStore({ storage, masterKey, fortressId });
  const writes: NodeToRelayInput[] = [], audits: HermesBridgeAuditRecord[] = [];
  const core = new HermesBridgeCore({ agentId: "agent", abort: new AbortController(), adapter,
    writeFrame: frame => writes.push(frame), appendAudit: async row => {
      audits.push(row); if (rejectAudit) throw new Error("audit fixture");
    }, nowMs: () => now, setTimer: () => ({}), clearTimer() {} });
  core.relayFrame({ kind: "accepted", connectionId: "c1" });
  const frame = (value: Record<string, unknown>) => {
    const publicBytes = Buffer.from(JSON.stringify(value));
    core.relayFrame({ kind: "frame", connectionId: "c1", publicBytes, publicFrame: parsePublicFrame(publicBytes) });
  };
  const call = (id: string) => frame({ type: "tools_call", request_id: id, name: "memory_recall", arguments: { query: "board meeting" } });
  const body = () => {
    const response = writes.filter(row => row.type === "response").at(-1)!;
    if (response.type !== "response") throw new Error("response absent");
    return JSON.parse(JSON.parse(Buffer.from(response.publicPayloadBytes).toString()).payload.content[0].text);
  };
  return { storage, adapter, corpus, core, audits, writes, call, frame, body,
    complete: () => { complete = true; }, advance: () => { now += RECALL_WALL_BUDGET_MS; },
    rejectAudit: (value: boolean) => { rejectAudit = value; } };
}

it("recalls verified context while the ledger is latched", async () => {
  const h = await fixture();
  try {
    h.rejectAudit(true); h.call("first");
    await drainUntil(() => h.writes.length > 0);
    expect(h.body().outcome).toBe("unavailable"); expect(h.core.snapshot().ledger.latched).toBe(true);
    h.rejectAudit(false); h.writes.length = 0; h.call("latched");
    await drainUntil(() => h.writes.length > 0);
    expect(h.body()).toEqual(MATCH);
  } finally { h.core.relayEof(); }
});

it.each(["provenance", "hash", "unsigned"] as const)("recall observes the %s trust boundary", async boundary => {
  const h = await fixture();
  try {
    const id = "mem.agent.a";
    if (boundary === "provenance") {
      const document = (await h.corpus.getDocument(id))!;
      await h.corpus.putDocument({ ...document, content_hash: passageContentHash("different content") }, "user_content");
    } else if (boundary === "hash") {
      const chunk = (await h.corpus.getChunk(id, 0, `c${padChunkOrdinal(0)}`))!;
      expect(chunk).not.toBeNull();
      await h.corpus.putChunk({ ...chunk, text: "changed board", content_hash: passageContentHash("changed board") }, "user_content");
    } else {
      await h.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(id)); h.complete();
    }
    h.call("trust"); await drainUntil(() => h.writes.length > 0);
    expect(h.body()).toEqual(boundary === "provenance"
      ? { outcome: "recalled", context: "", passages: [], truncated: false }
      : { outcome: "unavailable", message: "Sanctuary could not take this request right now; nothing was done." });
    expect(h.audits.filter(row => row.kind === "memory_recall").flatMap(row => row.passage_ids ?? [])).toEqual([]);
  } finally { h.core.relayEof(); }
});

it.each(["cancel", "stop"] as const)("finishes bounded recall work after %s with a retained match", async control => {
  const h = await fixture();
  await h.adapter.insertPassage({ passage_id: "b", text: "board later" }, "user_content");
  const originalRead = h.storage.read.bind(h.storage);
  let release!: () => void, parked = false;
  const pause = new Promise<void>(resolve => { release = resolve; });
  h.storage.read = async (namespace, key) => {
    if (key === "doc.mem.agent.b") { parked = true; await pause; }
    return originalRead(namespace, key);
  };
  try {
    h.call("controlled"); await drainUntil(() => parked);
    if (control === "cancel") h.frame({ type: "cancel", mcp_request_id: "controlled" }); else h.core.relayEof();
    h.advance(); release();
    await drainUntil(() => h.audits.some(row => row.kind === "memory_recall"));
    expect(h.audits.find(row => row.kind === "memory_recall")).toMatchObject({ passage_ids: ["a"], truncated: true });
    await drainUntil(() => h.core.snapshot().lifecycle.recordCount === 0);
    if (control === "cancel") expect(h.body()).toEqual({ ...MATCH, truncated: true });
    else expect(h.writes).toEqual([]);
  } finally { release(); h.core.relayEof(); }
});
