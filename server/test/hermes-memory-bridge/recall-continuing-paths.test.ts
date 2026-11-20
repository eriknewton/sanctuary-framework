// Recall uses the production encrypted adapter and preserves trust checks through the bridge.
import { describe, expect, it } from "vitest";
import { HermesBridgeCore, type HermesBridgeAuditRecord } from "../../src/hermes-memory-bridge/bridge-core.js";
import { parsePublicFrame, type NodeToRelayInput } from "../../src/hermes-memory-bridge/envelopes.js";
import { HermesRecallBudget, RECALL_VERIFY_CANDIDATES, RECALL_VERIFY_RESERVE_MS, RECALL_WALL_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { SdwDocumentCorpusStore, padChunkOrdinal } from "../../src/sdw/document-corpus-store.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE, type SdwMemoryIntegrityState } from "../../src/sdw/records.js";
import { documentProvenanceKey } from "../../src/sdw/grammar.js";
import { passageContentHash } from "../../src/sdw/write-gate.js";
import { TestSdwMemoryBackendAdapter } from "../sdw/test-memory-backend.js";
import { KeyOrderMemoryStorage, QUERY, recallFixture, settle, type Seed } from "../sdw/recall-score-first-fixture.js";

const CREATED = "2026-11-01T00:00:00.000Z";
const MATCH = { outcome: "recalled", context: "- (saved 2026-11-01) board meeting\n",
  passages: [{ passage_id: "a", created_at: CREATED }], truncated: false };
async function drainUntil(condition: () => boolean) {
  // One thousand microtask turns bound this in-memory harness; no wall-clock sleeps or stalled I/O.
  for (let turn = 0; turn < 1000 && !condition(); turn++) await Promise.resolve();
  expect(condition()).toBe(true);
}
async function fixture(options: { readonly readAhead?: number } = {}) {
  const storage = new KeyOrderMemoryStorage(), masterKey = new Uint8Array(32).fill(17), fortressId = "recall-paths";
  let complete = false, now = 0, rejectAudit = false;
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey, fortressId, ownerRef: "agent", now: () => CREATED,
    resolveMemoryIntegrityState: async () => complete ? "state_COMPLETE" : "state_PRE_MIGRATION" });
  await adapter.insertPassage({ passage_id: "a", text: "board meeting" }, "user_content");
  const corpus = new SdwDocumentCorpusStore({ storage, masterKey, fortressId });
  const writes: NodeToRelayInput[] = [], audits: HermesBridgeAuditRecord[] = [];
  const { readAhead } = options;
  // The bridge builds each recall budget itself; a pinned window replaces only that budget's readAhead limit.
  const recallAdapter = readAhead === undefined ? adapter : Object.assign(Object.create(adapter) as typeof adapter, {
    recallPassages: (budget: HermesRecallBudget) => adapter.recallPassages(
      Object.defineProperty(budget, "limits", { value: Object.freeze({ ...budget.limits, readAhead }) })),
  });
  const core = new HermesBridgeCore({ completeAuditInsert() {}, agentId: "agent", abort: new AbortController(), adapter: recallAdapter,
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
    complete: () => { complete = true; }, advance: (ms = RECALL_WALL_BUDGET_MS) => { now += ms; },
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

it.each(["cancel", "stop"] as const)("finishes bounded recall work after %s, returning only verified matches", async control => {
  // Pinned to one passage at a time: this clock jumps when b's read is issued, which the read-ahead does before a
  // commits; memory-recall-read-ahead-clock.test.ts covers the default window on a clock driven by read completion.
  const h = await fixture({ readAhead: 1 });
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
    // The scan stops at the verification reserve, and the reserved slice verifies the match ranked before it.
    h.advance(RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS); release();
    await drainUntil(() => h.audits.some(row => row.kind === "memory_recall"));
    // Stop aborts the call, and an abort returns only passages that had verified; none had during the scan.
    expect(h.audits.find(row => row.kind === "memory_recall"))
      .toMatchObject({ passage_ids: control === "cancel" ? ["a"] : [], truncated: true });
    await drainUntil(() => h.core.snapshot().lifecycle.recordCount === 0);
    if (control === "cancel") expect(h.body()).toEqual({ ...MATCH, truncated: true });
    else expect(h.writes).toEqual([]);
  } finally { release(); h.core.relayEof(); }
});

describe("continuing arms of the read-ahead recall, each with the evidence it checks", () => {
  /** The adapter-level fixture, with listings and integrity-state reads counted. */
  async function counted(seeds: readonly Seed[], state: SdwMemoryIntegrityState | ((read: number) => SdwMemoryIntegrityState) = "state_PRE_MIGRATION") {
    const f = await recallFixture();
    for (const seed of seeds) await f.seed(seed);
    let integrityReads = 0, listings = 0;
    f.setState(async () => { integrityReads++; return typeof state === "function" ? state(integrityReads) : state; });
    const list = f.storage.list.bind(f.storage);
    f.storage.list = async (namespace, prefix) => { listings++; return list(namespace, prefix); };
    f.storage.writes = 0;
    return { f, counts: () => ({ integrityReads, listings }) };
  }
  const seed = (passageId: string, kind: Seed["kind"] = "valid", text = "alpha bravo"): Seed => ({ kind, passageId, text, createdAt: CREATED });
  const nine = (kind: Seed["kind"]) => Array.from({ length: 9 }, (_, n) => seed(`n${n}`, kind)); // Nine: one more than RECALL_VERIFY_CANDIDATES.
  const empty = { outcome: "recalled", context: "", passages: [], truncated: false };

  it("an empty normalized query answers empty, reading no listing and no integrity state", async () => {
    const { f, counts } = await counted([seed("a")], "state_MARKER_ABSENT_POST_COMPLETE");
    expect(await f.adapter.recallPassages(f.budget("the and when"))).toEqual(empty);
    expect(counts()).toEqual({ integrityReads: 0, listings: 0 });
  });

  it.each(["aborted", "expired"] as const)("a budget already %s at entry answers empty and truncated, as inherited, reading no integrity state", async kind => {
    // Inherited early return: it checks the budget only; it reads neither the listing nor the integrity state, so it
    // answers even when the state would refuse a scan. It returns no passage.
    const { f, counts } = await counted([seed("a")], "state_MARKER_ABSENT_POST_COMPLETE");
    const abort = new AbortController();
    let now = 0;
    const budget = new HermesRecallBudget(QUERY, () => now, abort.signal);
    if (kind === "aborted") abort.abort(); else now = RECALL_WALL_BUDGET_MS;
    expect(await f.adapter.recallPassages(budget)).toEqual({ ...empty, truncated: true });
    expect(counts()).toEqual({ integrityReads: 0, listings: 0 });
  });

  it("an empty listing answers empty, reading no integrity state", async () => {
    const { f, counts } = await counted([], "state_MARKER_ABSENT_POST_COMPLETE");
    expect(await f.adapter.recallPassages(f.budget())).toEqual(empty);
    expect(counts()).toEqual({ integrityReads: 0, listings: 1 });
  });

  it.each(["no match", "only skipped passages"] as const)("a complete scan with %s answers empty only after the end integrity read", async kind => {
    const seeds = kind === "no match" ? [seed("a", "valid", "garden budget"), seed("b", "valid", "kitchen flight")]
      : [seed("a", "quarantined"), seed("b", "bad-signer"), seed("c", "unresolved-signer")];
    const steady = await counted(seeds);
    expect(await steady.f.adapter.recallPassages(steady.f.budget())).toEqual(empty);
    expect(steady.counts().integrityReads).toBe(2);
    expect(steady.f.storage.writes).toBe(0);
    // The property: the end read is checked on this arm too, so a state that moved during the scan refuses.
    const moved = await counted(seeds, read => read === 1 ? "state_PRE_MIGRATION" : "state_MIGRATING");
    await expect(moved.f.adapter.recallPassages(moved.f.budget())).rejects.toThrow("integrity state changed");
  });

  it("nine passages that pass the screen, fail verification and lack a chunk cost nine verifications and answer empty", async () => {
    const { f } = await counted(nine("invalid-with-broken-chunk"));
    const verifications = f.countVerifications();
    const outcome = await settle(() => f.adapter.recallPassages(f.budget()));
    // The chunk-failure arm verifies before deciding, once per broken passage; RECALL_VERIFY_CANDIDATES does not cap it.
    expect(verifications.count()).toBe(9);
    expect(verifications.count()).toBeGreaterThan(RECALL_VERIFY_CANDIDATES);
    expect(outcome).toEqual({ ok: true, value: empty });
    expect(f.storage.writes).toBe(0);
  });

  it("nine passages whose signer-eligibility check throws fall back to full verification in the screen and answer empty", async () => {
    const { f } = await counted(nine("is-marked-throws-invalid"));
    const verifications = f.countVerifications();
    const outcome = await settle(() => f.adapter.recallPassages(f.budget()));
    // The eligibility fallback is a full verification inside the screen, so inside a read-ahead slot, once per passage.
    expect(verifications.count()).toBe(9);
    expect(outcome).toEqual({ ok: true, value: empty });
    expect(f.storage.chunkReads).toBe(0);
    expect(f.storage.writes).toBe(0);
  });

  it("a recall whose peer vanished continues to its audit row with verified passages only", async () => {
    const h = await fixture();
    await h.adapter.insertPassage({ passage_id: "b", text: "board meeting again" }, "user_content");
    // b ranks first but its origin signature no longer verifies: it is scored, then refused by verification.
    const record = (await h.corpus.getProvenanceRaw("mem.agent.b"))!.record;
    const signature = record.companion.origin.signature;
    await h.corpus.putProvenance({ ...record, companion: { ...record.companion, origin: { ...record.companion.origin,
      signature: (signature[0] === "A" ? "B" : "A") + signature.slice(1) } } }, "system_generated");
    const originalRead = h.storage.read.bind(h.storage);
    let release!: () => void, parked = false;
    const pause = new Promise<void>(resolve => { release = resolve; });
    h.storage.read = async (namespace, key) => {
      if (key === "doc.mem.agent.b") { parked = true; await pause; }
      return originalRead(namespace, key);
    };
    try {
      h.call("vanished"); await drainUntil(() => parked);
      h.core.relayFrame({ kind: "closed", connectionId: "c1" });
      release();
      await drainUntil(() => h.audits.some(row => row.kind === "memory_recall"));
      expect(h.audits.find(row => row.kind === "memory_recall")).toMatchObject({ passage_ids: ["a"], truncated: false });
      expect(h.writes.filter(row => row.type === "response")).toEqual([]);
    } finally { release(); h.core.relayEof(); }
  });
});
