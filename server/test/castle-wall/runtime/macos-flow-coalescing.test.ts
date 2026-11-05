/** Admitted live flows share counted windows with fixed storage and work bounds. */
// fail-before-exempt: these assertions witness behavior the source already has; each is proven by a named mutation that fails it, so the file passes against unchanged source by construction.
import { describe, it, expect, vi } from "vitest";
import { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import type { AuditSink } from "../../../src/castle-wall/runtime/audit-consumer.js";
const load = () => import("../../../src/castle-wall/runtime/macos-flow-coalescing.js").catch(() => null);
const UID = 501; // Ordinary fixture principal.
const token = Buffer.from(new Uint32Array([0, UID, UID, UID, UID, 123, 1, 1]).buffer).toString("hex");
function fixture(sink?: AuditSink, pinnedProducerKeyB64url?: string) {
  let now = Date.parse("2026-11-04T00:00:00Z");
  const entries: Array<{ operation: string; details: Record<string, unknown> | undefined }> = [];
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", coalesceLiveFlows: true, pinnedProducerKeyB64url,
    auditSink: sink ?? { append(_layer, operation, _identity, details) { entries.push({ operation, details }); }, async flush() {} },
    now: () => now, defaultApprovalTimeoutSeconds: 30, approvalQueue: { async enqueue() {} },
    manifestProvider: { currentSnapshot() { throw new Error("unused fixture snapshot"); } },
  });
  return { consumer, entries, advance(ms: number) { now += ms; }, frame(ip = "192.0.2.1") { return {
    type: "flow_decision_recorded" as const, decision: "drop" as const, agent: { id: token, template: "fixture" },
    destination: { ip, port: 443, protocol: "tcp" as const, host: null, hostname_source: null, opaque: false },
    recorded_at: new Date(now).toISOString(),
  }; } };
}
function internalCoalescingSnapshot(consumer: MacOSFlowEventConsumer) {
  return (consumer as unknown as { coalescer: { snapshot(): ReturnType<import("../../../src/castle-wall/runtime/macos-flow-coalescing.js").FlowCoalescer["snapshot"]> } }).coalescer.snapshot();
}
function requireSummary(consumer: MacOSFlowEventConsumer) { expect(consumer.flushCoalescedFlowSummaries).toBeTypeOf("function"); }
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };

describe("counted flow windows", () => {
  it("a failed head does not admit its key", async () => {
    let attempts = 0; let losses = 0;
    const f = fixture({ append(_layer, operation, _identity, details) {
      if (operation === "castle_wall_ingress_discarded") losses += (details!.counts as Record<string, number>).audit_persist_failed!;
      if (operation === "egress_blocked" && ++attempts === 1) throw new Error("fixture primary failure");
    }, async flush() {} });
    requireSummary(f.consumer);
    const module = await load(); expect(module).not.toBeNull();
    const classifications = vi.spyOn(module!.FlowCoalescer.prototype, "classify");
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await expect(f.consumer.handleFlowDecisionRecorded(f.frame())).rejects.toThrow("fixture primary failure");
      await f.consumer.handleFlowDecisionRecorded(f.frame());
      expect(classifications.mock.results[1]!.value.kind, "second delivery is a primary head").toBe("head");
      expect(attempts, "each head attempts primary persistence").toBe(2);
      expect(f.consumer.getStats()).toMatchObject({ decisionsCoalesced: 0, decisionsRecorded: 1 });
      await f.consumer.drainIngressDrops();
      expect(losses, "one failed delivery owns one unconfirmed attempt").toBe(1);
    } finally { classifications.mockRestore(); log.mockRestore(); }
  });
  it("a failed later head preserves older reserved evidence", async () => {
    const f = fixture(); requireSummary(f.consumer);
    const module = await load(); expect(module).not.toBeNull();
    const coalescer = new module!.FlowCoalescer("fixture", () => 0);
    const metadata = module!.flowCoalescingMetadata("fixture/uid-501", { dest_ip: "192.0.2.1", dest_port: 443, dest_protocol: "tcp", decision: "drop" });
    const first = coalescer.classify(metadata); if (first.kind === "head") first.settled(true);
    coalescer.classify(metadata); coalescer.closeWindows();
    const reservation = [...coalescer.reservations()][0]!;
    const before = JSON.stringify(reservation.record);
    const next = coalescer.classify(metadata); if (next.kind === "head") next.settled(false);
    expect(coalescer.snapshot().coalesced_evidence_pending).toBe(1);
    expect(JSON.stringify([...coalescer.reservations()][0]!.record)).toBe(before);
    expect(coalescer.classify(metadata).kind).toBe("head");
  });
  it("three arrivals produce one head and coalesced_count 2", async () => {
    const f = fixture(); requireSummary(f.consumer);
    for (let index = 0; index < 3; index++) await f.consumer.handleFlowDecisionRecorded(f.frame());
    await f.consumer.flushCoalescedFlowSummaries();
    expect(f.entries.map(entry => entry.operation)).toEqual(["egress_blocked", "castle_wall_flow_decisions_coalesced"]);
    expect(f.entries[1]?.details?.coalesced_count, "counted observations survive summary persistence").toBe(2);
  });
  it("summary interval matches the injected clock", async () => {
    const f = fixture(); requireSummary(f.consumer);
    await f.consumer.handleFlowDecisionRecorded(f.frame());
    f.advance(10); await f.consumer.handleFlowDecisionRecorded(f.frame());
    f.advance(30); await f.consumer.handleFlowDecisionRecorded(f.frame());
    await f.consumer.flushCoalescedFlowSummaries();
    expect(f.entries[1]?.details, "counted interval follows local receipt time").toMatchObject({ first_recorded_at: "2026-11-04T00:00:00.010Z", last_recorded_at: "2026-11-04T00:00:00.040Z", window_ms: 30 });
  });
  it("appends equal window heads plus summaries", async () => {
    const f = fixture(); requireSummary(f.consumer);
    const windows = 3, arrivals = 4; // Three explicit flush windows of four arrivals each.
    for (let window = 0; window < windows; window++) {
      for (let index = 0; index < arrivals; index++) await f.consumer.handleFlowDecisionRecorded(f.frame());
      await f.consumer.flushCoalescedFlowSummaries();
    }
    expect(f.entries.filter(entry => entry.operation === "egress_blocked"), "one primary per scheduled window").toHaveLength(windows);
    expect(f.entries, "one primary and one summary per nonempty window").toHaveLength(windows * 2);
  });
  it("held reservation plus new arrivals equals the pending snapshot", async () => {
    const gate = deferred(); let hold = true;
    const f = fixture({ async append(_l, operation) { if (operation === "castle_wall_flow_decisions_coalesced" && hold) { await gate.promise; throw new Error("fixture summary failure"); } }, async flush() {} });
    requireSummary(f.consumer);
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      for (let index = 0; index < 3; index++) await f.consumer.handleFlowDecisionRecorded(f.frame());
      const first = f.consumer.flushCoalescedFlowSummaries(); await turn();
      for (let index = 0; index < 3; index++) await f.consumer.handleFlowDecisionRecorded(f.frame());
      await f.consumer.flushCoalescedFlowSummaries();
      expect(f.consumer.getCoalescingSnapshot().coalesced_evidence_pending, "reservation plus mutable observations remain owned").toBe(4);
      expect(internalCoalescingSnapshot(f.consumer).max_records_per_key).toBe(2);
      gate.resolve(); await first;
      expect(f.consumer.getCoalescingSnapshot().coalesced_evidence_pending).toBe(4);
      hold = false; await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushCoalescedFlowSummaries();
      expect(f.consumer.getCoalescingSnapshot().coalesced_evidence_confirmed).toBe(4);
    } finally { hold = false; gate.resolve(); await f.consumer.drainCoalescedFlowSummaries(); log.mockRestore(); }
  });
  it("retries retire each observation once", async () => {
    const payloads: string[] = []; let fails = 2; // Two retry attempts precede confirmation.
    const f = fixture({ append(_l, operation, _id, details) { if (operation === "castle_wall_flow_decisions_coalesced") { payloads.push(JSON.stringify(details)); if (fails-- > 0) throw new Error("fixture failure"); } }, async flush() {} });
    requireSummary(f.consumer);
    for (let index = 0; index < 3; index++) await f.consumer.handleFlowDecisionRecorded(f.frame());
    for (let attempt = 0; attempt < 3; attempt++) await f.consumer.flushCoalescedFlowSummaries();
    expect(new Set(payloads).size, "retry content and identifier stay stable").toBe(1);
    expect(internalCoalescingSnapshot(f.consumer), "confirmation retires observations exactly once").toMatchObject({ coalesced_evidence_confirmed: 2, coalesced_evidence_pending: 0, coalescedSummariesWritten: 1, summary_write_failures: 2 });
  });
  it("retains at most FLOW_COALESCE_MAX_KEYS keys", async () => {
    const f = fixture(); requireSummary(f.consumer); const module = await load(); expect(module).not.toBeNull();
    const coalescer = new module!.FlowCoalescer("fixture", Date.now);
    for (let index = 0; index < module!.FLOW_COALESCE_MAX_KEYS + 1; index++) coalescer.classify({ subject: "fixture/uid-501", destination: { ip: `192.0.${Math.floor(index / 256)}.${index % 256}`, port: 443, protocol: "tcp", host: null }, decision: "drop" });
    expect(coalescer.snapshot().keys, "simultaneously retained keys respect the cap").toBe(module!.FLOW_COALESCE_MAX_KEYS);
    expect(coalescer.snapshot().keys_overflowed).toBe(1);
  });
  it("over-limit fields pass through without retained bytes", async () => {
    const f = fixture(); requireSummary(f.consumer); const module = await load(); expect(module).not.toBeNull();
    const coalescer = new module!.FlowCoalescer("fixture", Date.now);
    const metadata = module!.flowCoalescingMetadata("fixture/uid-501", { dest_ip: "192.0.2.1", dest_port: 443, dest_protocol: "tcp", decision: "drop", dest_host: "x".repeat(module!.FLOW_COALESCE_MAX_RECORD_BYTES) });
    expect(metadata).not.toBeNull();
    expect(coalescer.classify(metadata).kind).toBe("head");
    expect(coalescer.snapshot().retained_bytes, "complete record byte gate refuses retention independently of key size").toBe(0);
  });
  it("one key visit per arrival", async () => {
    const f = fixture(); requireSummary(f.consumer); const module = await load(); expect(module).not.toBeNull();
    const coalescer = new module!.FlowCoalescer("fixture", Date.now);
    const arrivals = 20; // Multiple simultaneously open keys distinguish a lookup from traversal.
    for (let index = 0; index < arrivals; index++) coalescer.classify({ subject: "fixture/uid-501", destination: { ip: `192.0.2.${index}`, port: 443, protocol: "tcp", host: null }, decision: "drop" });
    expect(coalescer.snapshot().key_visits, "arrivals visit only their addressed key").toBe(arrivals);
  });
});

import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { MacOSFlowIpcListener } from "../../../src/castle-wall/runtime/macos-ipc-listener.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import { EmissionLivenessWatchdog } from "../../../src/castle-wall/audit/emission-liveness.js";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
const FLOW_COALESCE_TEST_SAME_KEY_FRAMES = 3_000; // Sixty seconds at fifty arrivals per second.
const FLOW_COALESCE_TEST_DISTINCT_KEYS = 300; // Crosses the 256-key retention limit.
const FLOW_COALESCE_TEST_HEAP_BOUND_BYTES = 32 * 1024 * 1024; // Measured 32 MiB retained-heap regression ceiling.
const FLOW_COALESCE_TEST_TIMEOUT_MS = 15 * 60_000; // Workload allowance, never an assertion deadline.
setFlagsFromString("--expose-gc");
const collectGarbage = runInNewContext("gc") as () => void;
it("a coalescible frame waits behind a held head", async () => {
  requireSummary(fixture().consumer);
  const root = await mkdtemp("/tmp/cw-held-head-"); vi.stubEnv("HOME", root);
  const key = ed25519.utils.randomPrivateKey(), pin = Buffer.from(ed25519.getPublicKey(key)).toString("base64url");
  const storage = new FilesystemStorage(join(root, "state"));
  const audit = new AuditLog(storage, key, { checkpointInterval: 0, integrityMode: "lenient" });
  const gate = deferred(), entered = deferred(); let holding = false;
  const write = storage.writeDurable.bind(storage);
  const writeSpy = vi.spyOn(storage, "writeDurable").mockImplementation(async (...args) => {
    if (holding && args[0] === "_audit" && args[1].startsWith("entry-")) { holding = false; entered.resolve(); await gate.promise; }
    return write(...args);
  });
  const now = Date.now();
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", coalesceLiveFlows: true, pinnedProducerKeyB64url: pin, now: () => now,
    auditSink: { append: (...args) => audit.append(...args), flush: () => audit.flushDurable() }, defaultApprovalTimeoutSeconds: 30,
    approvalQueue: { async enqueue() {} }, manifestProvider: { currentSnapshot() { throw new Error("unused"); } },
  });
  requireSummary(consumer);
  const listener = new MacOSFlowIpcListener({ socketPath: join(root, "unused.sock"), consumer });
  const connection = { subscriberId: "fixture", registered: false, inbound: new Uint8Array(), telemetryBytes: 0, socket: { write() { return true; }, destroy() {} } };
  const dispatch = (notification: unknown) => (listener as unknown as { dispatchFrame(state: unknown, body: string): void }).dispatchFrame(connection, JSON.stringify({ jsonrpc: "2.0", method: "castle-wall.flow_decision_recorded", params: notification }));
  function signed(seq: number, prior: string | null, ip = "192.0.2.1") {
    const notification = fixture().frame(ip); notification.recorded_at = new Date(now).toISOString();
    const body = canonicalize({ timestamp: notification.recorded_at, layer: "l1", operation: "egress_blocked", identity_id: token, result: "blocked",
      details: { agent_id: token, dest_ip: ip, dest_port: 443, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
    return { ...notification, producer: { event_canonical_json: body, captured_at_unix_ms: now, seq, prior_sha256_hex: prior,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, now, seq), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } };
  }
  const hash = (body: string) => createHash("sha256").update(body).digest("hex");
  const zero = signed(0, null), one = signed(1, hash(zero.producer.event_canonical_json), "192.0.2.2"), two = signed(2, hash(one.producer.event_canonical_json));
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    dispatch(zero); await vi.waitFor(() => expect(consumer.getFlowChainState()?.lastAckedSeq).toBe(0));
    holding = true; dispatch(one); await entered.promise;
    const charge = connection.telemetryBytes; dispatch(two); await turn();
    expect(consumer.getFlowChainState()?.lastAckedSeq, "later coalescible admission cannot complete before its held predecessor").toBe(0);
    expect(consumer.getStats().decisionsCoalesced).toBe(0);
    expect(connection.telemetryBytes, "waiting admission keeps its listener charge").toBeGreaterThan(charge);
    gate.resolve(); await vi.waitFor(() => expect(consumer.getFlowChainState()?.lastAckedSeq).toBe(2));
    expect(consumer.getFlowChainState()?.lastEventChainHash).toBe(hash(two.producer.event_canonical_json));
    dispatch(two); await vi.waitFor(() => expect(consumer.getStats().duplicate_settled).toBe(1));
    expect(consumer.getStats().decisionsCoalesced).toBe(1);
    dispatch(signed(2, two.producer.prior_sha256_hex, "192.0.2.3"));
    await vi.waitFor(() => expect(consumer.getStats().rejection_confirmed).toBe(1));
    expect((await audit.query({ layer: "l1" })).entries.at(-1)?.details?.reason).toBe("seq_regression");
  } finally { holding = false; gate.resolve(); await consumer.drainFlowAdmission(); await audit.flush(); await turn(); writeSpy.mockRestore(); log.mockRestore(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }); }
});

it.each(["coalesced arrivals leave the watchdog unchanged", "one head decision note per window"])("%s", async () => {
  const watchdog = new EmissionLivenessWatchdog({ now: () => 0, onStall() {}, onRecovery() {} });
  const f = fixture();
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", coalesceLiveFlows: true, emissionLiveness: watchdog,
    auditSink: { append() {}, async flush() {} }, defaultApprovalTimeoutSeconds: 30, approvalQueue: { async enqueue() {} }, manifestProvider: { currentSnapshot() { throw new Error("unused"); } } });
  requireSummary(consumer);
  await consumer.handleFlowDecisionRecorded(f.frame()); const before = watchdog.snapshot();
  await consumer.handleFlowDecisionRecorded(f.frame()); await consumer.handleFlowDecisionRecorded(f.frame());
  expect(watchdog.snapshot(), "counted arrivals do not change any watchdog counter").toEqual(before);
  expect(watchdog.snapshot().decidedTotal, "one eligible window contributes one head decision").toBe(1);
});
it("conserves mixed delivery and summary ownership", async () => {
  let failPrimary = false, failSummary = true; const gate = deferred(); let holdSummary = true;
  const f = fixture({ async append(_l, operation) {
    if (operation === "egress_blocked" && failPrimary) throw new Error("fixture primary failure");
    if (operation === "castle_wall_flow_decisions_coalesced") { if (holdSummary) await gate.promise; if (failSummary) throw new Error("fixture summary failure"); }
  }, async flush() {} }); requireSummary(f.consumer);
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  function conserved() {
    const stats = f.consumer.getStats(), c = f.consumer.getCoalescingSnapshot();
    expect(stats.received, "each delivery has one owner").toBe(stats.waiting_or_in_flight + stats.primary_confirmed + stats.coalesced + stats.rejection_confirmed + stats.duplicate_settled + stats.delivery_unconfirmed_or_discarded);
    expect(stats.coalesced, "each counted observation has one evidence owner").toBe(c.coalesced_evidence_pending + c.coalesced_evidence_confirmed);
    return { stats, c };
  }
  try {
    for (let index = 0; index < 3; index++) await f.consumer.handleFlowDecisionRecorded(f.frame());
    const writing = f.consumer.flushCoalescedFlowSummaries(); await turn();
    await f.consumer.handleFlowDecisionRecorded(f.frame()); await f.consumer.handleFlowDecisionRecorded(f.frame());
    failPrimary = true; await expect(f.consumer.handleFlowDecisionRecorded(f.frame("192.0.2.2"))).rejects.toThrow("fixture primary failure"); failPrimary = false;
    await f.consumer.handleFlowDecisionRecorded({ ...f.frame(), recorded_at: "" });
    conserved(); gate.resolve(); await writing; conserved();
    holdSummary = false; failSummary = false; await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushCoalescedFlowSummaries();
    const measured = conserved();
    console.info("flow conservation", JSON.stringify(measured));
    expect(measured.stats).toMatchObject({ received: 7, primary_confirmed: 2, coalesced: 3, rejection_confirmed: 1, delivery_unconfirmed_or_discarded: 1, waiting_or_in_flight: 0 });
    expect(measured.c).toMatchObject({ coalesced_evidence_confirmed: 3, coalesced_evidence_pending: 0, summary_write_failures: 1 });
  } finally { holdSummary = false; failSummary = false; gate.resolve(); await f.consumer.drainCoalescedFlowSummaries(); log.mockRestore(); }
});
it("stays within fixed bounds under a sustained same-key stream", async () => {
  const initial = fixture(); requireSummary(initial.consumer); const module = await load(); expect(module).not.toBeNull();
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    for (const healthy of [true, false]) {
      let primaries = 0, summaries = 0;
      const f = fixture({ append(_l, operation) { if (operation === "egress_blocked") primaries++; if (operation === "castle_wall_flow_decisions_coalesced") summaries++; if (!healthy) throw new Error("fixture sink failure"); }, async flush() {} });
      collectGarbage(); const before = process.memoryUsage().heapUsed;
      const perWindow = 50; // Fifty arrivals per one-second injected window.
      for (let index = 0; index < FLOW_COALESCE_TEST_SAME_KEY_FRAMES; index++) {
        await f.consumer.handleFlowDecisionRecorded(f.frame()).catch(() => undefined); f.advance(1000 / perWindow);
        if ((index + 1) % perWindow === 0) await f.consumer.flushCoalescedFlowSummaries();
      }
      const expectedHeads = healthy ? FLOW_COALESCE_TEST_SAME_KEY_FRAMES / perWindow : FLOW_COALESCE_TEST_SAME_KEY_FRAMES;
      expect(primaries, "primary writes equal independently scheduled heads").toBe(expectedHeads);
      if (healthy) expect(summaries).toBe(expectedHeads);
      for (let index = 0; index < FLOW_COALESCE_TEST_DISTINCT_KEYS; index++) await f.consumer.handleFlowDecisionRecorded(f.frame(`198.51.${Math.floor(index / 256)}.${index % 256}`)).catch(() => undefined);
      const c = internalCoalescingSnapshot(f.consumer), stats = f.consumer.getStats();
      expect(c.keys).toBeLessThanOrEqual(module!.FLOW_COALESCE_MAX_KEYS);
      expect(c.max_records_per_key).toBeLessThanOrEqual(module!.FLOW_COALESCE_MAX_RECORDS_PER_KEY);
      expect(c.retained_bytes).toBeLessThanOrEqual(module!.FLOW_COALESCE_MAX_KEYS * (module!.FLOW_COALESCE_MAX_KEY_BYTES + module!.FLOW_COALESCE_MAX_RECORDS_PER_KEY * module!.FLOW_COALESCE_MAX_RECORD_BYTES));
      expect(c.coalesced_evidence_pending + c.coalesced_evidence_confirmed).toBe(stats.coalesced);
      expect(stats.received).toBe(stats.waiting_or_in_flight + stats.primary_confirmed + stats.coalesced + stats.rejection_confirmed + stats.duplicate_settled + stats.delivery_unconfirmed_or_discarded);
      collectGarbage(); const heapDelta = process.memoryUsage().heapUsed - before;
      expect(heapDelta).toBeLessThan(FLOW_COALESCE_TEST_HEAP_BOUND_BYTES);
      expect(c.key_visits).toBe(FLOW_COALESCE_TEST_SAME_KEY_FRAMES + FLOW_COALESCE_TEST_DISTINCT_KEYS);
      console.info("flow complexity", JSON.stringify({ sink: healthy ? "healthy" : "rejecting", stats, snapshot: c, heapDelta }));
    }
    await heldListenerWorkload(module!);
    exerciseMetadataBounds(module!);
  } finally { log.mockRestore(); }
}, FLOW_COALESCE_TEST_TIMEOUT_MS);

it("a failed pinned head remains a head after another key retires primary debt", async () => {
  const now = Date.now(), key = ed25519.utils.randomPrivateKey();
  let fail = false, attempts = 0;
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", coalesceLiveFlows: true,
    pinnedProducerKeyB64url: Buffer.from(ed25519.getPublicKey(key)).toString("base64url"), now: () => now,
    auditSink: { append(_l, operation) { if (operation === "egress_blocked") { attempts++; if (fail) throw new Error("fixture primary failure"); } }, async flush() {} },
    defaultApprovalTimeoutSeconds: 30, approvalQueue: { async enqueue() {} },
    manifestProvider: { currentSnapshot() { throw new Error("unused"); } },
  });
  requireSummary(consumer);
  let prior: string | null = null;
  const signed = (seq: number, ip: string) => {
    const frame = fixture().frame(ip); frame.recorded_at = new Date(now).toISOString();
    const body = canonicalize({ timestamp: frame.recorded_at, layer: "l1", operation: "egress_blocked", identity_id: token, result: "blocked",
      details: { agent_id: token, dest_ip: ip, dest_port: 443, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
    const notification = { ...frame, producer: { event_canonical_json: body, captured_at_unix_ms: now, seq, prior_sha256_hex: prior,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, now, seq), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } };
    prior = createHash("sha256").update(body).digest("hex"); return notification;
  };
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await consumer.handleFlowDecisionRecorded(signed(0, "192.0.2.1"));
    fail = true; await expect(consumer.handleFlowDecisionRecorded(signed(1, "192.0.2.2"))).rejects.toThrow("fixture primary failure");
    fail = false; await consumer.handleFlowDecisionRecorded(signed(2, "192.0.2.3"));
    await consumer.handleFlowDecisionRecorded(signed(3, "192.0.2.2"));
    expect(attempts, "a failed key has a new head after another primary clears debt").toBe(4);
    expect(consumer.getStats()).toMatchObject({ decisionsRecorded: 3, decisionsCoalesced: 0, delivery_unconfirmed_or_discarded: 1 });
  } finally { await consumer.drainIngressDrops(); log.mockRestore(); }
});

async function heldListenerWorkload(module: NonNullable<Awaited<ReturnType<typeof load>>>) {
  const root = await mkdtemp("/tmp/cw-counted-held-"); vi.stubEnv("HOME", root);
  const key = ed25519.utils.randomPrivateKey();
  const storage = new FilesystemStorage(join(root, "state"));
  const audit = new AuditLog(storage, key, { checkpointInterval: 0, integrityMode: "lenient" });
  await audit.append("l1", "fixture_start", "fixture");
  const gate = deferred(), entered = deferred(); let holding = true, activeWrites = 0, primaryWrites = 0;
  const write = storage.writeDurable.bind(storage);
  const spy = vi.spyOn(storage, "writeDurable").mockImplementation(async (...args) => {
    if (holding && args[0] === "_audit" && args[1].startsWith("entry-")) {
      activeWrites++; entered.resolve(); try { await gate.promise; } finally { activeWrites--; }
    }
    return write(...args);
  });
  const f = fixture({ append(...args) { if (args[1] === "egress_blocked") primaryWrites++; return audit.append(...args); }, flush: () => audit.flushDurable() });
  const listener = new MacOSFlowIpcListener({ socketPath: join(root, "unused.sock"), consumer: f.consumer });
  const origins = Array.from({ length: 16 }, (_, index) => ({ subscriberId: `fixture-${index}`, registered: false, inbound: new Uint8Array(), telemetryBytes: 0, socket: { write() { return true; }, destroy() {} } })); // Sixteen origins span the eight per-connection shares.
  const dispatch = (index: number) => (listener as unknown as { dispatchFrame(state: unknown, body: string): void }).dispatchFrame(origins[index % origins.length], JSON.stringify({ jsonrpc: "2.0", method: "castle-wall.flow_decision_recorded", params: f.frame() }));
  const charge = () => (listener as unknown as { telemetryBytes: number }).telemetryBytes;
  const globalBudget = 8 * 1024 * 1024, connectionBudget = globalBudget / 8; // Must match the listener's eight-MiB budget and eight shares.
  collectGarbage(); const initialHeap = process.memoryUsage().heapUsed;
  try {
    dispatch(0); await entered.promise;
    for (let index = 1; index < FLOW_COALESCE_TEST_SAME_KEY_FRAMES; index++) {
      dispatch(index); f.advance(1000 / 50); // Fifty arrivals per injected second.
      if (index % 50 === 0) await f.consumer.flushCoalescedFlowSummaries();
      expect(charge()).toBeLessThanOrEqual(globalBudget);
      expect(origins[index % origins.length]!.telemetryBytes).toBeLessThanOrEqual(connectionBudget);
    }
    expect(primaryWrites, "a held head keeps later admissions from starting primary storage").toBe(1);
    expect(activeWrites).toBe(1);
    expect(f.consumer.getStats().received).toBe(FLOW_COALESCE_TEST_SAME_KEY_FRAMES);
    expect(f.consumer.getFlowAdmissionSnapshot().unadmitted).toBeGreaterThan(0);
    const retained = charge(); await turn(); expect(charge()).toBe(retained);
    holding = false; gate.resolve();
    await vi.waitFor(() => expect(charge()).toBe(0), { timeout: 5000 }); // Filesystem settlement allowance, separate from stop tests.
    await f.consumer.drainIngressDrops(); await f.consumer.flushCoalescedFlowSummaries();
    const stats = f.consumer.getStats(), snapshot = internalCoalescingSnapshot(f.consumer);
    // The first held window closed at a scheduled flush; its successor owns the remaining admitted arrivals.
    expect(primaryWrites).toBe(2);
    expect(stats.received).toBe(stats.waiting_or_in_flight + stats.primary_confirmed + stats.coalesced + stats.rejection_confirmed + stats.duplicate_settled + stats.delivery_unconfirmed_or_discarded);
    expect(stats.coalesced).toBe(snapshot.coalesced_evidence_confirmed + snapshot.coalesced_evidence_pending);
    expect(snapshot.max_records_per_key).toBeLessThanOrEqual(module.FLOW_COALESCE_MAX_RECORDS_PER_KEY);
    expect(snapshot.keys).toBeLessThanOrEqual(module.FLOW_COALESCE_MAX_KEYS);
    collectGarbage(); const heapDelta = process.memoryUsage().heapUsed - initialHeap;
    expect(heapDelta).toBeLessThan(FLOW_COALESCE_TEST_HEAP_BOUND_BYTES);
    console.info("flow complexity", JSON.stringify({ sink: "held", stats, snapshot, heapDelta, retained }));
  } finally { f.consumer.closeFlowAdmission(); holding = false; gate.resolve(); await f.consumer.drainFlowAdmission(); await f.consumer.drainIngressDrops(); await audit.flush(); await turn(); spy.mockRestore(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }); }
}

function exerciseMetadataBounds(module: NonNullable<Awaited<ReturnType<typeof load>>>) {
  const metadata = (host: string | null = null) => ({ subject: "fixture/uid-501", destination: { ip: "192.0.2.1", port: 443, protocol: "tcp" as const, host }, decision: "drop" as const, seq: -Number.MAX_SAFE_INTEGER });
  const limit = module.FLOW_COALESCE_MAX_KEYS * (module.FLOW_COALESCE_MAX_KEY_BYTES + module.FLOW_COALESCE_MAX_RECORDS_PER_KEY * module.FLOW_COALESCE_MAX_RECORD_BYTES);
  function bounded(coalescer: InstanceType<typeof module.FlowCoalescer>) {
    const snapshot = coalescer.snapshot();
    expect(snapshot.keys).toBeLessThanOrEqual(module.FLOW_COALESCE_MAX_KEYS);
    expect(snapshot.max_records_per_key).toBeLessThanOrEqual(module.FLOW_COALESCE_MAX_RECORDS_PER_KEY);
    expect(snapshot.retained_bytes).toBeLessThanOrEqual(limit);
  }
  // Find the exact eligible host boundary independently by observing whether a key was retained.
  for (const character of ["x", "\"", "\\", "\u0000", "é", "😀"]) {
    let largest = -1;
    for (let length = 0; length <= module.FLOW_COALESCE_MAX_RECORD_BYTES; length++) {
      const coalescer = new module.FlowCoalescer("fixture", () => 0);
      coalescer.classify(metadata(character.repeat(length)));
      bounded(coalescer);
      if (coalescer.snapshot().keys === 0) break;
      largest = length;
    }
    expect(largest, "each encoding has an eligible boundary").toBeGreaterThan(0);
    const coalescer = new module.FlowCoalescer("fixture", () => 0);
    const candidate = metadata(character.repeat(largest));
    const head = coalescer.classify(candidate); if (head.kind === "head") head.settled(true);
    expect(coalescer.classify(candidate).kind).toBe("coalesced");
    bounded(coalescer); coalescer.closeWindows();
    const reservations = [...coalescer.reservations()];
    expect(reservations).toHaveLength(1);
    expect(Buffer.byteLength(JSON.stringify(reservations[0]!.record))).toBeLessThanOrEqual(module.FLOW_COALESCE_MAX_RECORD_BYTES);
    reservations[0]!.confirm(); expect(coalescer.snapshot().keys).toBe(0);
  }
  const coalescer = new module.FlowCoalescer("fixture", () => 0);
  const waves = 3; // Repeated complete key turnover exercises eviction without losing owed evidence.
  for (let wave = 0; wave < waves; wave++) {
    for (let index = 0; index < FLOW_COALESCE_TEST_DISTINCT_KEYS; index++) {
      const candidate = metadata(); candidate.destination.port += wave * FLOW_COALESCE_TEST_DISTINCT_KEYS + index;
      const visits = coalescer.snapshot().key_visits;
      const head = coalescer.classify(candidate); if (head.kind === "head") head.settled(true);
      coalescer.classify(candidate);
      expect(coalescer.snapshot().key_visits - visits).toBeLessThanOrEqual(2 * module.FLOW_COALESCE_MAX_KEY_VISITS_PER_FRAME);
      bounded(coalescer);
    }
    coalescer.closeWindows();
    const reservations = [...coalescer.reservations()];
    expect(reservations).toHaveLength(module.FLOW_COALESCE_MAX_SUMMARIES_PER_FLUSH);
    for (const reservation of reservations) reservation.confirm();
    expect([...coalescer.reservations()]).toHaveLength(0);
    expect(coalescer.snapshot().keys).toBe(0);
  }
  for (const invalid of [null, module.flowCoalescingMetadata("fixture", { dest_protocol: "other" }), metadata("x".repeat(module.FLOW_COALESCE_MAX_RECORD_BYTES + 1))]) {
    expect(coalescer.classify(invalid).kind).toBe("head"); expect(coalescer.snapshot().keys).toBe(0);
  }
}

it("counter limits retain exact pending ownership", async () => {
  const f = fixture(); requireSummary(f.consumer); const module = await load(); expect(module).not.toBeNull();
  const metadata = module!.flowCoalescingMetadata("fixture", { dest_ip: "192.0.2.1", dest_port: 443, dest_protocol: "tcp", decision: "drop" });
  for (const counter of ["counted", "sequence"] as const) {
    const coalescer = new module!.FlowCoalescer("fixture", () => 0);
    (coalescer as unknown as Record<string, number>)[counter] = Number.MAX_SAFE_INTEGER;
    expect(coalescer.classify(metadata).kind).toBe("head"); expect(coalescer.snapshot().keys).toBe(0);
  }
  const gate = deferred();
  const held = fixture({ async append() { await gate.promise; }, async flush() {} });
  try {
    held.consumer.noteIngressDrop("audit_backpressure", Number.MAX_SAFE_INTEGER);
    await turn(); held.consumer.noteIngressDrop("audit_backpressure", Number.MAX_SAFE_INTEGER);
    expect(held.consumer.getIngressLossSnapshot()).toMatchObject({ counts: { audit_backpressure: Number.MAX_SAFE_INTEGER }, counters_lower_bound: true });
  } finally { gate.resolve(); await held.consumer.drainIngressDrops(); }
});

it("failed bootstrap preserves ordinary refusal and watchdog accounting", async () => {
  const now = Date.now(), key = ed25519.utils.randomPrivateKey();
  const watchdog = new EmissionLivenessWatchdog({ now: () => now, onStall() {}, onRecovery() {} });
  let attempts = 0;
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", coalesceLiveFlows: true, emissionLiveness: watchdog,
    pinnedProducerKeyB64url: Buffer.from(ed25519.getPublicKey(key)).toString("base64url"), now: () => now,
    auditSink: { append(_l, operation) { if (operation === "egress_blocked") { attempts++; throw new Error("fixture primary failure"); } }, async flush() {} },
    defaultApprovalTimeoutSeconds: 30, approvalQueue: { async enqueue() {} }, manifestProvider: { currentSnapshot() { throw new Error("unused"); } } });
  requireSummary(consumer); const log = vi.spyOn(console, "error").mockImplementation(() => {});
  let prior: string | null = null;
  const signed = (seq: number) => {
    const frame = fixture().frame(); frame.recorded_at = new Date(now).toISOString();
    const body = canonicalize({ timestamp: frame.recorded_at, layer: "l1", operation: "egress_blocked", identity_id: token, result: "blocked",
      details: { agent_id: token, dest_ip: frame.destination.ip, dest_port: 443, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
    const result = { ...frame, producer: { event_canonical_json: body, captured_at_unix_ms: now, seq, prior_sha256_hex: prior,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, now, seq), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } };
    prior = createHash("sha256").update(body).digest("hex"); return result;
  };
  try {
    await expect(consumer.handleFlowDecisionRecorded(signed(0))).rejects.toThrow("fixture primary failure");
    await consumer.handleFlowDecisionRecorded(signed(1));
    expect(attempts).toBe(1);
    expect(consumer.getStats()).toMatchObject({ decisionsCoalesced: 0, rejection_confirmed: 1, delivery_unconfirmed_or_discarded: 1 });
    expect(watchdog.snapshot()).toMatchObject({ decidedTotal: 2, emittedTotal: 0, rejectedTotal: 2 });
  } finally { await consumer.drainIngressDrops(); log.mockRestore(); }
});

it("arrivals addressing open keys perform one table lookup each", async () => {
  requireSummary(fixture().consumer); const module = await load(); expect(module).not.toBeNull();
  let operations = 0;
  class CountingMap<K, V> extends Map<K, V> {
    override get(key: K) { operations++; return super.get(key); }
    override has(key: K) { operations++; return super.has(key); }
    override set(key: K, value: V) { operations++; return super.set(key, value); }
    override *entries(): MapIterator<[K, V]> { for (const entry of super.entries()) { operations++; yield entry; } }
    override *keys(): MapIterator<K> { for (const key of super.keys()) { operations++; yield key; } }
    override *values(): MapIterator<V> { for (const value of super.values()) { operations++; yield value; } }
    override [Symbol.iterator]() { return this.entries(); }
    override forEach(callback: (value: V, key: K, map: Map<K, V>) => void, thisArg?: unknown) {
      super.forEach((value, key) => { operations++; callback.call(thisArg, value, key, this); });
    }
  }
  const coalescer = new module!.FlowCoalescer("table-work", () => 0);
  (coalescer as unknown as { windows: Map<string, unknown> }).windows = new CountingMap();
  const metadata = (port: number) => ({ subject: "fixture/uid-501", destination: { ip: "192.0.2.1", port, protocol: "tcp" as const, host: null }, decision: "drop" as const });
  for (let index = 0; index < module!.FLOW_COALESCE_MAX_KEYS; index++) {
    const head = coalescer.classify(metadata(index)); if (head.kind === "head") head.settled(true);
  }
  operations = 0;
  const arrivals = module!.FLOW_COALESCE_MAX_KEYS * 2; // Two passes address every already-open key.
  const lookupsPerArrival = 1; // Existing-key classification needs only windows.get, with no table traversal.
  for (let index = 0; index < arrivals; index++) coalescer.classify(metadata(index % module!.FLOW_COALESCE_MAX_KEYS));
  expect(operations, "open-key arrivals perform at most one independently counted map operation each").toBeLessThanOrEqual(lookupsPerArrival * arrivals);
});

it("a key reopened during a held flush keeps its closed reservation and a new window", async () => {
  const gate = deferred(), entered = deferred(); let hold = true, reject = true;
  const payloads: Array<Record<string, unknown>> = [];
  const f = fixture({ async append(_l, operation, _id, details) {
    if (operation !== "castle_wall_flow_decisions_coalesced") return;
    payloads.push(structuredClone(details!));
    if (hold) { entered.resolve(); await gate.promise; }
    if (reject) throw new Error("fixture summary unavailable");
  }, async flush() {} }); requireSummary(f.consumer);
  try {
    for (const ip of ["192.0.2.1", "192.0.2.2"]) {
      await f.consumer.handleFlowDecisionRecorded(f.frame(ip)); await f.consumer.handleFlowDecisionRecorded(f.frame(ip));
    }
    const writing = f.consumer.flushCoalescedFlowSummaries(); await entered.promise;
    await f.consumer.handleFlowDecisionRecorded(f.frame("192.0.2.2"));
    await f.consumer.handleFlowDecisionRecorded(f.frame("192.0.2.2"));
    gate.resolve(); await writing; hold = false; reject = false;
    await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushCoalescedFlowSummaries();
    expect(payloads[1], "retry bytes keep the first immutable reservation").toEqual(payloads[0]);
    const secondKey = payloads.filter(record => (record.destination as { ip: string }).ip === "192.0.2.2");
    expect(secondKey.map(record => [record.coalesced_count, record.windows_merged]), "the closed reservation and reopened window each represent one window").toEqual([[1, 1], [1, 1]]);
    expect(new Set(secondKey.map(record => record.summary_seq)).size).toBe(2);
    expect(f.consumer.getCoalescingSnapshot().coalesced_evidence_confirmed).toBe(3);
  } finally { hold = false; reject = false; gate.resolve(); await f.consumer.drainCoalescedFlowSummaries(); }
});

it("expiry keeps windows and loss reservations unchanged", async () => {
  const f = fixture(); requireSummary(f.consumer);
  const module = await load(); expect(module).not.toBeNull();
  await f.consumer.handleFlowDecisionRecorded(f.frame()); await f.consumer.handleFlowDecisionRecorded(f.frame());
  f.consumer.lapseStopBudget();
  const internals = f.consumer as unknown as { coalescer: InstanceType<NonNullable<typeof module>["FlowCoalescer"]>; ingressReservation: unknown };
  const close = vi.spyOn(internals.coalescer, "closeWindows");
  const reserve = vi.spyOn(internals.coalescer, "reservations");
  const before = internals.coalescer.snapshot();
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    f.consumer.noteIngressDrop("audit_backpressure");
    await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushIngressDrops();
    expect(close, "expiry closes no further window").not.toHaveBeenCalled();
    expect(reserve, "expiry creates no further summary reservation").not.toHaveBeenCalled();
    expect(internals.coalescer.snapshot()).toEqual(before);
    expect(internals.ingressReservation, "expiry leaves pending loss outside a new reservation").toBeNull();
  } finally { close.mockRestore(); reserve.mockRestore(); log.mockRestore(); }
});

it.each(["summary", "loss"] as const)("a held %s append starts no flush after expiry", async kind => {
  const gate = deferred(), entered = deferred(); const calls: string[] = [];
  const operation = kind === "summary" ? "castle_wall_flow_decisions_coalesced" : "castle_wall_ingress_discarded";
  const f = fixture({ async append(_l, op) { calls.push(op); if (op === operation) { entered.resolve(); await gate.promise; } }, async flush() { calls.push("flush"); } });
  requireSummary(f.consumer); const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    if (kind === "summary") { await f.consumer.handleFlowDecisionRecorded(f.frame()); await f.consumer.handleFlowDecisionRecorded(f.frame()); }
    const writing = kind === "summary" ? f.consumer.flushCoalescedFlowSummaries() : (f.consumer.noteIngressDrop("audit_backpressure"), f.consumer.drainIngressDrops(() => false));
    await entered.promise; f.consumer.lapseStopBudget(); const before = [...calls];
    gate.resolve(); await writing;
    expect(calls, "late append settlement starts no flush or further evidence write").toEqual(before);
  } finally { gate.resolve(); await f.consumer.drainIngressDrops(); await f.consumer.drainCoalescedFlowSummaries(); log.mockRestore(); }
});

it("a pinned coalesced arrival changes no watchdog counter", async () => {
  const now = Date.now(), key = ed25519.utils.randomPrivateKey();
  const watchdog = new EmissionLivenessWatchdog({ now: () => now, onStall() {}, onRecovery() {} });
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", coalesceLiveFlows: true, emissionLiveness: watchdog,
    pinnedProducerKeyB64url: Buffer.from(ed25519.getPublicKey(key)).toString("base64url"), now: () => now,
    auditSink: { append() {}, async flush() {} }, defaultApprovalTimeoutSeconds: 30, approvalQueue: { async enqueue() {} },
    manifestProvider: { currentSnapshot() { throw new Error("unused"); } } });
  requireSummary(consumer); let prior: string | null = null;
  const signed = (seq: number) => {
    const notification = fixture().frame(); notification.recorded_at = new Date(now).toISOString();
    const body = canonicalize({ timestamp: notification.recorded_at, layer: "l1", operation: "egress_blocked", identity_id: token, result: "blocked",
      details: { agent_id: token, dest_ip: notification.destination.ip, dest_port: 443, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
    const result = { ...notification, producer: { event_canonical_json: body, captured_at_unix_ms: now, seq, prior_sha256_hex: prior,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, now, seq), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } };
    prior = createHash("sha256").update(body).digest("hex"); return result;
  };
  await consumer.handleFlowDecisionRecorded(signed(0)); const before = watchdog.snapshot();
  await consumer.handleFlowDecisionRecorded(signed(1));
  expect(consumer.getStats().decisionsCoalesced).toBe(1);
  expect(watchdog.snapshot(), "a pinned counted arrival changes no watchdog counter").toEqual(before);
});

it.each(["channel", "pinned"] as const)("detached %s storage settlement preserves reservation owners through repeated admission and stop", async mode => {
  requireSummary(fixture().consumer); const module = await load(); expect(module).not.toBeNull();
  const root = await mkdtemp("/tmp/cw-reservation-owners-");
  const key = ed25519.utils.randomPrivateKey(), storage = new FilesystemStorage(join(root, "state"));
  const holdDeadlineMs = 100; // A short real storage deadline separates caller rejection from detached settlement.
  const audit = new AuditLog(storage, key, { checkpointInterval: 0, integrityMode: "lenient", writeLockHoldDeadlineMs: holdDeadlineMs });
  const gate = deferred(), entered = deferred(); let hold = false;
  const payloads: Array<{ operation: string; bytes: string }> = [];
  const f = fixture({ append(...args) { payloads.push({ operation: args[1], bytes: JSON.stringify(args[3]) }); return audit.append(...args); }, flush: () => audit.flushDurable() }, mode === "pinned" ? Buffer.from(ed25519.getPublicKey(key)).toString("base64url") : undefined);
  const listener = new MacOSFlowIpcListener({ socketPath: join(root, "unused.sock"), consumer: f.consumer });
  const connection = { subscriberId: "fixture", registered: false, inbound: new Uint8Array(), telemetryBytes: 0, socket: { write() { return true; }, destroy() {} } };
  const boundary = listener as unknown as { dispatchFrame(state: unknown, body: string): void; removeConnection(state: unknown): void; telemetryBytes: number };
  let seq = 0, prior: string | null = null;
  const arrival = () => {
    const notification = f.frame();
    if (mode === "channel") return notification;
    const timestamp = Date.parse(notification.recorded_at);
    const body = canonicalize({ timestamp: notification.recorded_at, layer: "l1", operation: "egress_blocked", identity_id: token, result: "blocked",
      details: { agent_id: token, dest_ip: notification.destination.ip, dest_port: 443, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
    const result = { ...notification, producer: { event_canonical_json: body, captured_at_unix_ms: timestamp, seq, prior_sha256_hex: prior,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, timestamp, seq), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } };
    seq++; prior = createHash("sha256").update(body).digest("hex"); return result;
  };
  const dispatch = () => boundary.dispatchFrame(connection, JSON.stringify({ jsonrpc: "2.0", method: "castle-wall.flow_decision_recorded", params: arrival() }));
  const internals = f.consumer as unknown as { coalescer: InstanceType<NonNullable<typeof module>["FlowCoalescer"]> };
  const write = storage.writeDurable.bind(storage);
  const spy = vi.spyOn(storage, "writeDurable").mockImplementation(async (...args) => {
    if (hold && args[0] === "_audit" && args[1].startsWith("entry-")) { entered.resolve(); await gate.promise; }
    return write(...args);
  });
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  let summary: Promise<void> | undefined;
  try {
    await f.consumer.handleFlowDecisionRecorded(arrival()); await f.consumer.handleFlowDecisionRecorded(arrival());
    hold = true; summary = f.consumer.flushCoalescedFlowSummaries(); await entered.promise;
    await vi.waitFor(() => expect(audit.getWriteLockRecoveryCount()).toBeGreaterThan(0), { timeout: holdDeadlineMs * 20 }); // Room for filesystem deadline dispatch.
    const reserved = [...internals.coalescer.reservations()][0]!.record;
    const bytes = JSON.stringify(reserved);
    f.consumer.noteIngressDrop("audit_backpressure");
    const waves = 3, arrivals = module!.FLOW_COALESCE_MAX_KEYS; // Repeated waves cross storage deadlines while the old payload stays held.
    for (let wave = 0; wave < waves; wave++) {
      for (let index = 0; index < arrivals; index++) dispatch();
      await turn(); await f.consumer.flushCoalescedFlowSummaries();
      if (wave === 0) await vi.waitFor(() => expect(audit.getWriteLockRecoveryCount()).toBeGreaterThanOrEqual(3), { timeout: holdDeadlineMs * 20 });
      expect(f.consumer.getFlowAdmissionSnapshot().active, "a failed primary retains admission until its detached write settles").toBe(1);
      const snapshot = internals.coalescer.snapshot();
      expect(snapshot.keys).toBeLessThanOrEqual(module!.FLOW_COALESCE_MAX_KEYS);
      expect(snapshot.max_records_per_key).toBeLessThanOrEqual(module!.FLOW_COALESCE_MAX_RECORDS_PER_KEY);
      expect(snapshot.retained_bytes).toBeLessThanOrEqual(module!.FLOW_COALESCE_MAX_KEYS * (module!.FLOW_COALESCE_MAX_KEY_BYTES + module!.FLOW_COALESCE_MAX_RECORDS_PER_KEY * module!.FLOW_COALESCE_MAX_RECORD_BYTES));
      expect([...internals.coalescer.reservations()][0]!.record, "one immutable owner retains the reservation identifier").toBe(reserved);
      expect(JSON.stringify(reserved)).toBe(bytes);
    }
    const charged = boundary.telemetryBytes;
    expect(charged, "the detached head and its queued arrivals retain their listener charges").toBeGreaterThan(0);
    boundary.removeConnection(connection); await listener.stop();
    expect(boundary.telemetryBytes, "disconnect and stop retain the admitted storage charge").toBeGreaterThan(0);
    hold = false; gate.resolve(); await summary; await f.consumer.drainFlowAdmission(); await f.consumer.drainIngressDrops();
    await vi.waitFor(() => expect(boundary.telemetryBytes).toBe(0));
    await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushCoalescedFlowSummaries();
    const snapshot = internals.coalescer.snapshot();
    expect(snapshot.coalesced_evidence_confirmed + snapshot.coalesced_evidence_pending,
      "one immutable owner accounts for each observation after late settlement").toBe(f.consumer.getStats().coalesced);
    expect(snapshot.coalesced_evidence_pending).toBe(0);
    const summaries = payloads.filter(record => record.operation === "castle_wall_flow_decisions_coalesced");
    expect(summaries[1]?.bytes, "the uncertain summary retry keeps its identifier and bytes").toBe(summaries[0]?.bytes);
    const losses = payloads.filter(record => record.operation === "castle_wall_ingress_discarded");
    const lossOwners = new Map<number, string>();
    for (const record of losses) {
      const id = (JSON.parse(record.bytes) as { batch_seq: number }).batch_seq;
      if (lossOwners.has(id)) expect(record.bytes, "loss retries preserve one immutable reservation identifier").toBe(lossOwners.get(id));
      lossOwners.set(id, record.bytes);
    }
    expect(losses.length, "loss ownership survives disconnect and stop cancellation").toBeGreaterThan(1);
    const byIdentifier = new Map<number, string>();
    for (const record of summaries) {
      expect(Buffer.byteLength(record.bytes), "each settled summary respects the record byte cap").toBeLessThanOrEqual(module!.FLOW_COALESCE_MAX_RECORD_BYTES);
      const id = (JSON.parse(record.bytes) as { summary_seq: number }).summary_seq;
      if (byIdentifier.has(id)) expect(record.bytes, "one reservation identifier always denotes one immutable record").toBe(byIdentifier.get(id));
      byIdentifier.set(id, record.bytes);
    }
    const stats = f.consumer.getStats();
    expect(stats.received).toBe(stats.waiting_or_in_flight + stats.primary_confirmed + stats.coalesced + stats.rejection_confirmed + stats.duplicate_settled + stats.delivery_unconfirmed_or_discarded);
  } finally {
    hold = false; gate.resolve(); f.consumer.closeFlowAdmission(); await summary; await f.consumer.drainFlowAdmission();
    await f.consumer.drainIngressDrops(); await audit.flush(); spy.mockRestore(); log.mockRestore(); await rm(root, { recursive: true, force: true });
  }
});

import { AsyncLocalStorage } from "node:async_hooks";
const SINGLE_OWNER = 1; // One writer owns each immutable reservation until caller and storage settle.
const HOLD_DEADLINE_MS = 100; // Short real lock hold; setup and cleanup have separate timeout headroom.
const SERIAL_DEADLINES = 2; // Summary and loss expire independently, in that order.
const SETUP_TIMEOUT_MS = HOLD_DEADLINE_MS * 100; // Filesystem setup and recovery polling have one hundred hold intervals.
const OWNER_TIMEOUT_MS = SETUP_TIMEOUT_MS * 3 + SERIAL_DEADLINES * HOLD_DEADLINE_MS; // Setup, schedule and cleanup plus both deadlines.
const SUMMARY_OPERATION = "castle_wall_flow_decisions_coalesced";
const LOSS_OPERATION = "castle_wall_ingress_discarded";
// Caller rejection cannot retire an attempt while its raw entry write still owns storage work.
function ownershipLedger(audit: AuditLog, storage: FilesystemStorage) {
  type Attempt = { id: string; operation: string; token: symbol; callerSettled: boolean; children: number; error?: unknown; active: boolean };
  const context = new AsyncLocalStorage<Attempt>();
  const attempts: Attempt[] = [];
  const activeAttempts = new Map<string, number>(), outstandingPhysicalWrites = new Map<string, number>();
  const highAttempts = new Map<string, number>(), highWrites = new Map<string, number>(), totalPhysicalWrites = new Map<string, number>();
  const selected = new Map<string, string>(), bytes = new Map<string, string>();
  const gates = new Map<string, ReturnType<typeof deferred>>(), entries = new Map<string, ReturnType<typeof deferred>>();
  const recoveries: Array<{ reason: string }> = [];
  const settled: Promise<unknown>[] = [];
  const payloads: Array<{ operation: string; details: Record<string, unknown> | undefined }> = [];
  let hold = true;
  audit.onWriteLockRecovery(event => { recoveries.push(event); });
  const increment = (map: Map<string, number>, id: string, amount: number) => map.set(id, (map.get(id) ?? 0) + amount);
  const retire = (attempt: Attempt) => {
    if (attempt.active && attempt.callerSettled && attempt.children === 0) {
      attempt.active = false; increment(activeAttempts, attempt.id, -SINGLE_OWNER);
    }
  };
  for (const operation of [SUMMARY_OPERATION, LOSS_OPERATION]) { gates.set(operation, deferred()); entries.set(operation, deferred()); }
  const append = audit.append.bind(audit);
  const appendSpy = vi.spyOn(audit, "append").mockImplementation((...args) => {
    const operation = args[1], details = args[3]; payloads.push({ operation, details });
    if (operation !== SUMMARY_OPERATION && operation !== LOSS_OPERATION) return append(...args);
    const id = JSON.stringify([operation, details!.consumer_instance_id, details!.summary_seq ?? details!.batch_seq]);
    const serialized = JSON.stringify(details);
    if (!bytes.has(id)) bytes.set(id, serialized);
    else expect(serialized, "an identifier retains its original bytes").toBe(bytes.get(id));
    if (!selected.has(operation)) selected.set(operation, id);
    const attempt: Attempt = { id, operation, token: Symbol(id), callerSettled: false, children: 0, active: true };
    attempts.push(attempt); increment(activeAttempts, id, SINGLE_OWNER);
    highAttempts.set(id, Math.max(highAttempts.get(id) ?? 0, activeAttempts.get(id)!));
    const original = context.run(attempt, () => append(...args));
    settled.push(original.then(() => { attempt.callerSettled = true; retire(attempt); }, error => {
      attempt.error = error; attempt.callerSettled = true; retire(attempt);
    }));
    return original;
  });
  const write = storage.writeDurable.bind(storage);
  const writeSpy = vi.spyOn(storage, "writeDurable").mockImplementation(async (...args) => {
    const attempt = context.getStore();
    if (!attempt || args[0] !== "_audit" || !args[1].startsWith("entry-")) return write(...args);
    attempt.children++; increment(outstandingPhysicalWrites, attempt.id, SINGLE_OWNER); increment(totalPhysicalWrites, attempt.id, SINGLE_OWNER);
    highWrites.set(attempt.id, Math.max(highWrites.get(attempt.id) ?? 0, outstandingPhysicalWrites.get(attempt.id)!));
    try {
      if (hold && selected.get(attempt.operation) === attempt.id) {
        entries.get(attempt.operation)!.resolve();
        await gates.get(attempt.operation)!.promise;
        // A late fixture failure leaves the production successor's persisted chain intact.
        throw new Error("fixture late entry unavailable");
      }
      return await write(...args);
    } finally { attempt.children--; increment(outstandingPhysicalWrites, attempt.id, -SINGLE_OWNER); retire(attempt); }
  });
  return {
    attempts, activeAttempts, outstandingPhysicalWrites, totalPhysicalWrites, highAttempts, highWrites, selected, payloads, recoveries,
    async deadline(operation: string, count: number) {
      await vi.waitFor(() => expect(outstandingPhysicalWrites.get(selected.get(operation)!)).toBe(SINGLE_OWNER), { timeout: SETUP_TIMEOUT_MS });
      await entries.get(operation)!.promise;
      await vi.waitFor(() => {
        expect(recoveries).toHaveLength(count);
        const attempt = attempts.find(item => item.id === selected.get(operation))!;
        expect(attempt.callerSettled).toBe(true);
        expect(attempt.error).toMatchObject({ name: "AuditLockHoldDeadlineError", deadlineMs: HOLD_DEADLINE_MS });
      }, { timeout: SETUP_TIMEOUT_MS });
      expect(recoveries.at(-1)?.reason).toBe("write_lock_hold_deadline_exceeded");
    },
    exclusive(operations = [SUMMARY_OPERATION, LOSS_OPERATION]) {
      for (const operation of operations) {
        const id = selected.get(operation)!; expect(id).toBeDefined();
        expect(activeAttempts.get(id), `${operation} active attempts`).toBe(SINGLE_OWNER);
        expect(outstandingPhysicalWrites.get(id), `${operation} outstanding entry writes`).toBe(SINGLE_OWNER);
      }
      for (const count of highAttempts.values()) expect(count, "exclusive attempt high-water").toBeLessThanOrEqual(SINGLE_OWNER);
      for (const count of highWrites.values()) expect(count, "exclusive entry-write high-water").toBeLessThanOrEqual(SINGLE_OWNER);
      expect(new Set(attempts.filter(item => item.active).map(item => item.token)).size).toBe(attempts.filter(item => item.active).length);
    },
    release() { hold = false; for (const gate of gates.values()) gate.resolve(); },
    async join() {
      await Promise.all(settled);
      await vi.waitFor(() => {
        expect([...activeAttempts.values()].every(count => count === 0)).toBe(true);
        expect([...outstandingPhysicalWrites.values()].every(count => count === 0)).toBe(true);
      }, { timeout: SETUP_TIMEOUT_MS });
    },
    restore() { appendSpy.mockRestore(); writeSpy.mockRestore(); context.disable(); },
  };
}

async function ownedFixture(mode: string) {
  const root = await mkdtemp("/tmp/cw-exclusive-");
  const key = ed25519.utils.randomPrivateKey(), storage = new FilesystemStorage(join(root, "state"));
  const audit = new AuditLog(storage, key, { checkpointInterval: 0, integrityMode: "lenient", writeLockHoldDeadlineMs: HOLD_DEADLINE_MS });
  const f = fixture({ append: (...args) => audit.append(...args), flush: () => audit.flushDurable() }, mode === "pinned" ? Buffer.from(ed25519.getPublicKey(key)).toString("base64url") : undefined);
  const listener = new MacOSFlowIpcListener({ socketPath: join(root, "unused.sock"), consumer: f.consumer });
  const boundary = listener as unknown as { dispatchFrame(state: unknown, body: string): void; removeConnection(state: unknown): void; telemetryBytes: number };
  const connection = (id: string) => ({ subscriberId: id, registered: false, inbound: new Uint8Array(), telemetryBytes: 0, socket: { write() { return true; }, destroy() {} } });
  let seq = 0, prior: string | null = null;
  const arrival = (ip = "192.0.2.1") => {
    const notification = f.frame(ip);
    if (mode === "channel") return notification;
    const timestamp = Date.parse(notification.recorded_at);
    const body = canonicalize({ timestamp: notification.recorded_at, layer: "l1", operation: "egress_blocked", identity_id: token, result: "blocked",
      details: { agent_id: token, dest_ip: ip, dest_port: notification.destination.port, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
    const result = { ...notification, producer: { event_canonical_json: body, captured_at_unix_ms: timestamp, seq, prior_sha256_hex: prior,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, timestamp, seq), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } };
    seq++; prior = createHash("sha256").update(body).digest("hex"); return result;
  };
  const ledger = ownershipLedger(audit, storage);
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  const module = await load(); expect(module).not.toBeNull();
  const internals = f.consumer as unknown as { coalescer: InstanceType<NonNullable<typeof module>["FlowCoalescer"]> };
  const classify = vi.spyOn(internals.coalescer, "classify");
  const frame = (ip?: string) => JSON.stringify({ jsonrpc: "2.0", method: "castle-wall.flow_decision_recorded", params: arrival(ip) });
  const origin = connection("settled");
  const dispatchSettled = async (ip?: string) => {
    const count = classify.mock.calls.length;
    boundary.dispatchFrame(origin, frame(ip));
    await vi.waitFor(() => { expect(classify.mock.calls.length).toBe(count + 1); expect(boundary.telemetryBytes).toBe(0); }, { timeout: SETUP_TIMEOUT_MS, interval: 1 }); // One millisecond polling only joins real I/O.
  };
  return { ...f, audit, storage, ledger, listener, boundary, connection, arrival, frame, origin, classify, internals, module: module!, dispatchSettled,
    async cleanup() {
      ledger.release(); f.consumer.closeFlowAdmission();
      await ledger.join(); await f.consumer.drainFlowAdmission(); await f.consumer.drainCoalescedFlowSummaries(); await f.consumer.drainIngressDrops();
      await audit.flush(); await ledger.join(); ledger.restore(); classify.mockRestore(); stderr.mockRestore();
      await rm(root, { recursive: true, force: true });
    } };
}

it.each(["channel", "pinned"])("exclusive summary and loss attempts survive storage deadlines: %s", async mode => {
  const f = await ownedFixture(mode); let summary: Promise<void> | undefined;
  const retriesStarted: Promise<void>[] = [];
  const retrySummary = () => { retriesStarted.push(f.consumer.flushCoalescedFlowSummaries()); };
  try {
    await f.dispatchSettled(); await f.dispatchSettled();
    expect(f.consumer.getStats().decisionsCoalesced).toBe(1);
    summary = f.consumer.flushCoalescedFlowSummaries();
    await f.ledger.deadline(SUMMARY_OPERATION, 1); f.ledger.exclusive([SUMMARY_OPERATION]);
    retrySummary(); f.consumer.noteIngressDrop("audit_backpressure");
    await turn(); f.ledger.exclusive([SUMMARY_OPERATION]);
    await f.ledger.deadline(LOSS_OPERATION, SERIAL_DEADLINES);
    retrySummary(); f.consumer.noteIngressDrop("audit_backpressure");
    await turn(); f.ledger.exclusive();
    const retries = 2; // Repeat both explicit opportunities while the same raw writes remain held.
    for (let index = 0; index < retries; index++) {
      retrySummary(); f.consumer.noteIngressDrop("audit_backpressure");
      await turn(); f.ledger.exclusive();
    }
    const pending = f.consumer.getCoalescingSnapshot().coalesced_evidence_pending;
    const losses = f.consumer.getIngressLossSnapshot().counts.audit_backpressure;
    expect(pending).toBe(1); expect(losses).toBe(SERIAL_DEADLINES + retries);
    f.ledger.release(); await summary; await f.ledger.join();
    await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushIngressDrops(); await f.ledger.join();
    const snapshot = f.consumer.getCoalescingSnapshot();
    expect(snapshot.coalesced_evidence_pending).toBe(0); expect(snapshot.coalesced_evidence_confirmed).toBe(pending);
    expect(snapshot.coalesced_evidence_pending + snapshot.coalesced_evidence_confirmed).toBe(f.consumer.getStats().coalesced);
    expect(f.consumer.getIngressLossSnapshot().counts.audit_backpressure).toBe(0);
    for (const id of f.ledger.selected.values()) expect(f.ledger.totalPhysicalWrites.get(id)).toBe(SERIAL_DEADLINES); // Original attempt plus sequential retry.
    const confirmedLosses = f.ledger.payloads.filter(record => record.operation === LOSS_OPERATION).slice(SINGLE_OWNER)
      .reduce((sum, record) => sum + (record.details!.counts as Record<string, number>).audit_backpressure!, 0);
    expect(confirmedLosses + f.consumer.getIngressLossSnapshot().counts.audit_backpressure).toBe(losses);
    expect(f.ledger.recoveries).toHaveLength(SERIAL_DEADLINES);
    const before = f.ledger.payloads.length; await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushIngressDrops();
    expect(f.ledger.payloads).toHaveLength(before);
    console.info("exclusive attempt ledger", JSON.stringify({ highAttempts: [...f.ledger.highAttempts], highWrites: [...f.ledger.highWrites], totalPhysicalWrites: [...f.ledger.totalPhysicalWrites], pending, losses }));
  } finally { f.ledger.release(); await summary; await Promise.all(retriesStarted); await f.cleanup(); }
}, OWNER_TIMEOUT_MS);
