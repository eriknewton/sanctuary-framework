// Recall writes nothing to the memory corpus and quarantines nothing under every schedule of the read-ahead's fault
// table, with a corpus holding newly invalid passages (valid when saved, failing verification now, not yet
// quarantined) that rank first, so a recall that quarantined on a failed verification would write.
import { describe, expect, it } from "vitest";
import { HermesBridgeCore, type HermesBridgeAuditRecord } from "../../src/hermes-memory-bridge/bridge-core.js";
import { parsePublicFrame } from "../../src/hermes-memory-bridge/envelopes.js";
import {
  HermesRecallBudget,
  RECALL_READ_AHEAD_PASSAGES,
  RECALL_VERIFY_RESERVE_MS,
  RECALL_WALL_BUDGET_MS,
  type HermesRecallLimits,
} from "../../src/hermes-memory-bridge/recall.js";
import { documentKey, documentProvenanceKey } from "../../src/sdw/grammar.js";
import { NOW, QUERY, prng, recallFixture, settle, type Seed } from "./recall-score-first-fixture.js";

// Newly invalid passages rank first: they hold every query word, twice.
const NEWLY_INVALID: Seed = { kind: "invalid-signature", passageId: "a-newly-invalid", text: "alpha bravo charlie alpha bravo charlie", createdAt: NOW };
const NEWLY_INVALID_BROKEN: Seed = { kind: "invalid-with-broken-chunk", passageId: "b-newly-invalid-broken", text: "alpha bravo charlie alpha", createdAt: NOW };
const VALID = Array.from({ length: 8 }, (_, n): Seed => ({ kind: "valid", passageId: `v${n}`, text: `alpha note ${n}`, createdAt: NOW }));
const turn = () => new Promise<void>(resolve => setImmediate(resolve));

async function corpus() {
  const f = await recallFixture({ readAhead: RECALL_READ_AHEAD_PASSAGES });
  for (const seed of [NEWLY_INVALID, NEWLY_INVALID_BROKEN, ...VALID]) await f.seed(seed);
  f.storage.writes = 0;
  return f;
}
type Corpus = Awaited<ReturnType<typeof corpus>>;
const docOf = (f: Corpus, passageId: string) => documentKey(f.documentIdOf(passageId));

/** Run one recall at the default window with the given clock, signal and limits. */
async function recall(f: Corpus, options: { nowMs?: () => number; signal?: AbortSignal; tighten?: Partial<HermesRecallLimits> } = {}) {
  const budget = new HermesRecallBudget(QUERY, options.nowMs ?? (() => f.storage.now), options.signal ?? new AbortController().signal,
    { ...options.tighten, readAhead: RECALL_READ_AHEAD_PASSAGES });
  return settle(() => f.adapter.recallPassages(budget));
}

/** Park reads whose key matches until released; the rest pass through. */
function parking(f: Corpus, match: (key: string) => boolean) {
  const parked: (() => void)[] = [];
  f.storage.beforeRead = key => match(key) ? new Promise<void>(resolve => parked.push(resolve)) : undefined;
  return { parked, release: () => { for (const release of parked.splice(0)) release(); } };
}

const adapterSchedules: Record<string, (f: Corpus) => Promise<unknown>> = {
  "the scan stops at the verification reserve": async f => {
    f.storage.beforeRead = key => { if (key === docOf(f, "v3")) f.storage.now = RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS; };
    return recall(f);
  },
  "the full wall during the scan": async f => {
    f.storage.beforeRead = key => { if (key === docOf(f, "v3")) f.storage.now = RECALL_WALL_BUDGET_MS; };
    return recall(f);
  },
  "the full wall during verification": async f => {
    f.countVerifications(count => { if (count === 2) f.storage.now = RECALL_WALL_BUDGET_MS; });
    return recall(f);
  },
  "an abort during the scan": async f => {
    const abort = new AbortController();
    f.storage.beforeRead = key => { if (key === docOf(f, "v3")) abort.abort(); };
    return recall(f, { signal: abort.signal });
  },
  "an abort during verification": async f => {
    const abort = new AbortController();
    f.countVerifications(count => { if (count === 2) abort.abort(); });
    return recall(f, { signal: abort.signal });
  },
  "a read past the stop point completes late": async f => {
    // The candidate cap stops the scan at v0 (fourth in key order); v1's read, in the same window, is parked.
    const gate = parking(f, key => key === docOf(f, "v1"));
    const call = recall(f, { tighten: { candidates: 3 } });
    for (let n = 0; n < 50; n++) await turn(); // Fifty turns: the scan has stopped and is held by the drain.
    expect(gate.parked.length).toBe(1);
    gate.release();
    return call;
  },
  "repeated waves aborted at different points": async f => {
    const outcomes = [];
    for (let wave = 0; wave < VALID.length; wave++) {
      const abort = new AbortController();
      f.storage.beforeRead = key => { if (key === docOf(f, `v${wave}`)) abort.abort(); };
      outcomes.push(await recall(f, { signal: abort.signal }));
    }
    return outcomes;
  },
  "concurrent calls with shuffled completion": async f => {
    const random = prng(0x0f1e);
    f.storage.beforeRead = async () => { for (let n = Math.floor(random() * 4); n > 0; n--) await turn(); };
    return Promise.all(Array.from({ length: 8 }, () => recall(f, { nowMs: () => 0 }))); // Eight: HERMES_MAX_CALL_RECORDS.
  },
  "a read error at a passage the commit reaches": async f => {
    f.storage.corrupt.add(docOf(f, "v2"));
    const outcome = await recall(f);
    expect(outcome.ok).toBe(false);
    return outcome;
  },
  "a read error past the stop point": async f => {
    f.storage.corrupt.add(docOf(f, "v1")); // Read ahead in the first window, past the candidate cap.
    const outcome = await recall(f, { tighten: { candidates: 3 } });
    expect(outcome.ok).toBe(true);
    return outcome;
  },
  "a provenance record replaced between the read-ahead and verification": async f => {
    f.storage.beforeRead = key => { if (key === docOf(f, "v4")) f.storage.corrupt.add(documentProvenanceKey(f.documentIdOf("v0"))); };
    return recall(f);
  },
  "random completion order": async f => {
    const random = prng(0x0f1f);
    f.storage.beforeRead = async () => { for (let n = Math.floor(random() * 4); n > 0; n--) await turn(); };
    return recall(f, { nowMs: () => 0 });
  },
};

/** The bridge over the same corpus, for the outside signals of the cancellation table. */
function bridge(f: Corpus) {
  const audits: HermesBridgeAuditRecord[] = [];
  const core = new HermesBridgeCore({ completeAuditInsert() {}, agentId: "agent", abort: new AbortController(), adapter: f.adapter,
    writeFrame: () => {}, appendAudit: async row => { audits.push(row); }, nowMs: () => 0, setTimer: () => ({}), clearTimer() {} });
  core.relayFrame({ kind: "accepted", connectionId: "c1" });
  const frame = (value: Record<string, unknown>) => {
    const publicBytes = Buffer.from(JSON.stringify(value));
    core.relayFrame({ kind: "frame", connectionId: "c1", publicBytes, publicFrame: parsePublicFrame(publicBytes) });
  };
  frame({ type: "tools_call", request_id: "r1", name: "memory_recall", arguments: { query: QUERY } });
  return { core, audits, frame };
}
const bridgeSchedules: Record<string, (b: ReturnType<typeof bridge>) => void> = {
  "a public cancel": b => b.frame({ type: "cancel", mcp_request_id: "r1" }),
  "a peer disconnect": b => b.core.relayFrame({ kind: "closed", connectionId: "c1" }),
  "a process stop": b => b.core.relayEof(),
  "a relay shutdown": b => b.core.relayFrame({ kind: "relay_shutdown" }),
};

describe("recall writes nothing to the corpus and quarantines nothing", () => {
  it.each(Object.keys(adapterSchedules))("under %s", async name => {
    const f = await corpus();
    await adapterSchedules[name]!(f);
    expect(f.storage.writes).toBe(0);
    // Neither newly invalid passage has a quarantine status record, so a later recall verifies them again.
    f.storage.beforeRead = undefined;
    for (const seed of [NEWLY_INVALID, NEWLY_INVALID_BROKEN]) expect(await f.corpus.getProvenanceStatusRaw(f.documentIdOf(seed.passageId))).toBeNull();
  });

  it.each(Object.keys(bridgeSchedules))("through the bridge, under %s with a read parked", async name => {
    const f = await corpus();
    const gate = parking(f, key => key === docOf(f, "v1"));
    const b = bridge(f);
    for (let n = 0; n < 50 && gate.parked.length === 0; n++) await turn();
    expect(gate.parked.length).toBe(1);
    bridgeSchedules[name]!(b);
    gate.release();
    for (let n = 0; n < 500 && b.core.snapshot().lifecycle.recordCount > 0; n++) await turn();
    expect(b.core.snapshot().lifecycle.recordCount).toBe(0);
    expect(f.storage.writes).toBe(0);
    expect(b.audits.filter(row => row.kind === "memory_recall")).toHaveLength(1);
    b.core.relayEof();
  });

  it("the newly invalid passage does reach verification, so a quarantining recall would have written", async () => {
    const f = await corpus();
    const verifications = f.countVerifications();
    const outcome = await recall(f, { nowMs: () => 0 });
    // Positive control for the zero counts above: both newly invalid passages were verified and refused.
    expect(verifications.count()).toBeGreaterThanOrEqual(2);
    expect(outcome.ok && outcome.value.passages.map(passage => passage.passage_id)).toEqual(["v0", "v1", "v2"]);
    expect(f.storage.writes).toBe(0);
  });
});
