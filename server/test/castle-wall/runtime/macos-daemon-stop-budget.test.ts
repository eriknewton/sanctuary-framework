/** Production flow composition flushes counted evidence and completes stop within one budget. */
import { afterEach, describe, expect, it, vi, onTestFinished } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { startMacOSCastleWallDaemon, type MacOSCastleWallListenerOptions } from "../../../src/castle-wall/runtime/macos-daemon.js";
import { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import type { AuditLog } from "../../../src/operational/audit-log.js";
import { CASTLE_WALL_STOP_DEADLINE_MS, CASTLE_WALL_STOP_EXIT_DEADLINE_MS, FLOW_STOP_FINAL_RECORD_RESERVE_MS } from "../../../src/castle-wall/constants.js";
import * as custodyFs from "../../../src/storage/custody-fs.js";
import { generateFullAgentPlist } from "../../../src/cli/castle-wall-full-agent.js";
// Must match CASTLE_WALL_STOP_TEST_SLACK_MS in test/cli/castle-wall-stop-backstop.test.ts: one fake-clock millisecond.
const CASTLE_WALL_STOP_TEST_SLACK_MS = 1;
const D = CASTLE_WALL_STOP_DEADLINE_MS / FLOW_STOP_FINAL_RECORD_RESERVE_MS;
const EPS = CASTLE_WALL_STOP_TEST_SLACK_MS;
const BUDGET = 100; // Short injected budget exercised entirely with fake time.
const UID = 501; // Ordinary fixture principal.
const TOKEN = Buffer.from(new Uint32Array([0, UID, UID, UID, UID, 123, 1, 1]).buffer).toString("hex");
const flow = () => ({ type: "flow_decision_recorded" as const, decision: "drop" as const,
  agent: { id: TOKEN, template: "fixture" }, destination: { ip: "192.0.2.1", port: 443, protocol: "tcp" as const, host: null, hostname_source: null, opaque: false }, recorded_at: new Date().toISOString() });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
function requireSummary() {
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", auditSink: { append() {}, async flush() {} }, defaultApprovalTimeoutSeconds: 30,
    approvalQueue: { async enqueue() {} }, manifestProvider: { currentSnapshot() { throw new Error("unused"); } } });
  expect(consumer.flushCoalescedFlowSummaries).toBeTypeOf("function");
}
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.useRealTimers(); });
async function fixture(held = "none", budget = BUDGET) {
  const home = await mkdtemp("/tmp/cw-stop-budget-");
  const gate = deferred(), entered = deferred(), finalEntered = deferred(); const calls: string[] = [];
  let stopping = false, started = false;
  const intervals = new Map<number, () => void>();
  const setInterval = globalThis.setInterval;
  vi.spyOn(globalThis, "setInterval").mockImplementation((callback, ms, ...args) => {
    intervals.set(ms as number, callback as () => void);
    return setInterval(callback, ms, ...args);
  });
  const key = ed25519.utils.randomPrivateKey();
  const entries: Array<{ operation: string; details?: Record<string, unknown> }> = [];
  const audit = { writeLockHoldDeadlineMs: BUDGET, onWriteLockRecovery() {},
    async append(_layer: string, operation: string, _identity: string, details?: Record<string, unknown>) {
      calls.push(operation);
      if (operation === "filter_stopped") finalEntered.resolve();
      if (held === "summary-reject" && operation === "castle_wall_flow_decisions_coalesced") throw new Error("fixture summary unavailable");
      if ((held === "final" && operation === "filter_stopped") || (held === "head" && operation === "egress_blocked") || (held === "summary" && operation === "castle_wall_flow_decisions_coalesced") ||
          (held === "loss" && operation === "castle_wall_ingress_discarded") ||
          (held === "non-agent" && operation === "castle_wall_non_agent_flows_observed") ||
          (held === "heartbeat" && started && operation === "castle_wall_heartbeat")) { entered.resolve(); await gate.promise; }
      entries.push({ operation, details });
    }, async flush() { calls.push("flush"); if (held === "final-flush" && stopping) { entered.resolve(); await gate.promise; } },
    async flushDurable() { calls.push("durable-flush"); },
    async query() { return { entries: [], total: 0 }; }, async getAuditChainVerdict() { return { status: "verified" }; },
  } as unknown as AuditLog;
  let options!: MacOSCastleWallListenerOptions;
  const handle = await startMacOSCastleWallDaemon({ fortressPath: home, fortressId: "fixture", masterKey: key, auditLog: audit,
    platform: "darwin", daemonMode: "safe", socketPath: join(home, "fixture.sock"), activeConfigPath: join(home, "active.json"),
    globalPinnedPublicKeyPath: join(home, "pin"), auditProducerPublicKeyPath: join(home, "producer"), auditProducerStatePath: null,
    stopDeadlineMs: budget, auditHeartbeatIntervalSeconds: 1, resolverLifecycleRefreshIntervalSeconds: 2, // Distinct fixture timer periods.
    systemResolverProvider: async () => { if (held === "resolver" && started) { entered.resolve(); await gate.promise; } return held === "publication" && started ? ["192.0.2.53"] : []; }, agentEgressProbe: async () => true,
    signerClientInvoke: async (args, data) => ({ code: 0, stderr: "", stdout: Buffer.from(args[0] === "get-pubkey" ? ed25519.getPublicKey(key) : ed25519.sign(data!, key)).toString("base64url") }),
    listenerFactory(opts) { options = opts; return {
      async start() {}, async stop() { calls.push("listener-stop"); if (held === "listener") { entered.resolve(); await gate.promise; } },
      async broadcastManifestUpdate() { if (held === "publication" && started) { entered.resolve(); await gate.promise; } return 0; }, async broadcastDecisionResponse() { return 0; }, recycleConnection() { return false; },
      async broadcastArmLease() { if (stopping) { calls.push("standdown"); if (held === "lease") { entered.resolve(); await gate.promise; } } return 0; },
    }; },
  });
  started = true;
  if (["head", "loss", "summary", "non-agent"].includes(held)) {
    const read = custodyFs.readFileCustody;
    // Single-hold fixtures keep unrelated cleanup prompt so fake time measures the selected hold.
    vi.spyOn(custodyFs, "readFileCustody").mockImplementation((...args) => {
      if (stopping && args[0] === join(home, "active.json")) return Promise.reject(Object.assign(new Error("fixture config absent"), { code: "ENOENT" }));
      return read(...args);
    });
  }
  if (held === "cleanup") {
    const read = custodyFs.readFileCustody;
    vi.spyOn(custodyFs, "readFileCustody").mockImplementation(async (...args) => {
      if (stopping && args[0] === join(home, "active.json")) { calls.push("cleanup"); entered.resolve(); await gate.promise; }
      return read(...args);
    });
  }
  return { consumer: options.consumer, calls, entries, entered, gate, finalEntered,
    prepareHold() { if (held === "resolver" || held === "publication") intervals.get(2000)!(); if (held === "heartbeat") intervals.get(1000)!(); },
    stop() { stopping = true; return handle.stop(); }, async cleanup() { gate.resolve(); await handle.stop(); await turn(); await rm(home, { recursive: true, force: true }); } };
}
describe("daemon stop budget", () => {
  it("stop budgets precede the launchd default window", () => {
    requireSummary();
    expect(CASTLE_WALL_STOP_DEADLINE_MS).toBeLessThan(CASTLE_WALL_STOP_EXIT_DEADLINE_MS);
    expect(CASTLE_WALL_STOP_EXIT_DEADLINE_MS).toBeLessThan(20_000); // launchd default window.
    expect(generateFullAgentPlist([process.execPath, "/opt/sanctuary/cli.js", "castle-wall", "daemon", "--fortress", "/tmp/fixture", "--launch-agent"])).not.toContain("ExitTimeOut");
  });
  it.each(["resolver", "heartbeat", "lease", "listener", "head", "loss", "summary", "non-agent", "final", "final-flush", "cleanup"])("stop settles within its budget plus slack: %s", async held => {
    requireSummary(); const f = await fixture(held); const log = vi.spyOn(console, "error").mockImplementation(() => {});
    let active: Promise<void> | undefined;
    try {
      f.prepareHold();
      if (held === "resolver" || held === "heartbeat") await f.entered.promise;
      if (held === "head") { active = f.consumer.handleFlowDecisionRecorded(flow()).catch(() => undefined); await f.entered.promise; }
      if (held === "loss") { f.consumer.noteIngressDrop("audit_backpressure"); await f.entered.promise; }
      if (held === "non-agent") await f.consumer.handleFlowDecisionRecorded({ ...flow(), agent: { id: Buffer.alloc(8 * Uint32Array.BYTES_PER_ELEMENT).toString("hex"), template: "fixture" } });
      if (held === "summary") { await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow()); }
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      let settled = false; const stop = f.stop().then(() => { settled = true; });
      await f.entered.promise;
      await vi.advanceTimersByTimeAsync(BUDGET + CASTLE_WALL_STOP_TEST_SLACK_MS);
      expect(settled, "stop completion flag is set within the shared budget").toBe(true);
      expect(log.mock.calls.filter(([line]) => String(line).includes("stop budget lapsed"))).toHaveLength(1);
      expect(f.consumer.getFlowAdmissionSnapshot().closed).toBe(true);
      const phase = ({ resolver: "RESOLVER_WAIT", heartbeat: "HEARTBEAT_IDLE", lease: "LEASE_STANDDOWN", listener: "LISTENER", head: "DRAINS", loss: "DRAINS", summary: "DRAINS", "non-agent": "DRAINS", final: "FINAL_RECORD", "final-flush": "FINAL_RECORD", cleanup: "CLEANUP" } as const)[held];
      const diagnostic = log.mock.calls.map(([line]) => String(line)).find(line => line.includes("stop budget lapsed"))!;
      const tokens = diagnostic.split(" ");
      const drainOnly = phase === "DRAINS";
      expect(tokens, diagnostic).toContain(`phase=state_STOP_${phase}`);
      expect(tokens).toContain(`lapse=${drainOnly ? "drain_cutoff" : "hard_expiry"}`);
      expect(tokens).toContain(`cutoff_state=state_STOP_${phase}`);
      expect(tokens).toContain(`hard_state=${drainOnly ? "none" : `state_STOP_${phase}`}`);
      expect(diagnostic).toContain(`pending_loss=${JSON.stringify(f.consumer.getIngressLossSnapshot())}`);
      expect(diagnostic).toContain(`pending_coalesced=${f.consumer.getCoalescingSnapshot().coalesced_evidence_pending}`);
      const admission = f.consumer.getFlowAdmissionSnapshot();
      expect(diagnostic).toContain(`unadmitted=${admission.unadmitted} active=${admission.active}`);
      expect(diagnostic).toContain(`pending_non_agent=${JSON.stringify(f.consumer.getNonAgentFlowCounters())}`);
      await stop;
      const before = [...f.calls]; f.gate.resolve(); await active; await turn();
      expect(f.calls, "late completion starts no further stop phase").toEqual(before);
      if (held === "head") expect(f.consumer.getStats().delivery_unconfirmed_or_discarded).toBe(1);
      expect(log.mock.calls.filter(([line]) => String(line).includes("stop budget lapsed"))).toHaveLength(1);
    } finally { f.gate.resolve(); await active; vi.useRealTimers(); await f.cleanup(); }
  });
  it("a late phase release starts no further stop phase", async () => {
    requireSummary(); const f = await fixture("listener"); vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] }); const stop = f.stop(); await f.entered.promise;
      await vi.advanceTimersByTimeAsync(BUDGET + CASTLE_WALL_STOP_TEST_SLACK_MS); await stop;
      const before = [...f.calls]; f.gate.resolve(); await turn();
      expect(f.calls, "late listener completion cannot start final persistence").toEqual(before);
      expect(f.calls).not.toContain("filter_stopped");
    } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
  });
  it("stop closes admission before draining", async () => {
    requireSummary(); const f = await fixture("head"); vi.spyOn(console, "error").mockImplementation(() => {});
    const active = f.consumer.handleFlowDecisionRecorded(flow()).catch(() => undefined); await f.entered.promise;
    let queuedSettled = false; const queued = f.consumer.handleFlowDecisionRecorded(flow()).then(() => { queuedSettled = true; });
    let later: Promise<void> | undefined;
    try {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] }); const stop = f.stop();
      let laterSettled = false;
      later = f.consumer.handleFlowDecisionRecorded(flow()).then(() => { laterSettled = true; });
      await turn();
      expect(queuedSettled, "queued unadmitted delivery settles without releasing its head").toBe(true);
      expect(laterSettled, "post-stop delivery settles without releasing the active head").toBe(true);
      expect(f.consumer.getIngressLossSnapshot().counts.flow_shutdown + f.entries.reduce((sum, entry) => sum + ((entry.details?.counts as Record<string, number> | undefined)?.flow_shutdown ?? 0), 0), "both queued and later arrivals report shutdown").toBe(2);
      expect(f.consumer.getFlowAdmissionSnapshot().active).toBe(1);
      await vi.advanceTimersByTimeAsync(BUDGET + CASTLE_WALL_STOP_TEST_SLACK_MS); await stop;
    } finally { f.gate.resolve(); await active; await queued; await later; vi.useRealTimers(); await f.cleanup(); }
  });
  it("the final-record reserve scales with an injected short stop budget", async () => {
    requireSummary(); const f = await fixture("summary"); vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(FLOW_STOP_FINAL_RECORD_RESERVE_MS).toBe(CASTLE_WALL_STOP_DEADLINE_MS / D);
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      const stop = f.stop(); await f.entered.promise;
      const cutoff = BUDGET - Math.floor(BUDGET / D);
      await vi.advanceTimersByTimeAsync(cutoff - CASTLE_WALL_STOP_TEST_SLACK_MS);
      expect(f.calls, "the short budget keeps a positive drain interval").not.toContain("filter_stopped");
      await vi.advanceTimersByTimeAsync(CASTLE_WALL_STOP_TEST_SLACK_MS);
      await f.finalEntered.promise; await stop;
      expect(performance.now()).toBe(cutoff);
      expect(f.entries.some(entry => entry.operation === "filter_stopped")).toBe(true);
    } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
  });
  it("a drain that outlives its cutoff fences consumer writes and keeps ownership", async () => {
    requireSummary(); const f = await fixture("summary"); vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      const stop = f.stop(); await f.entered.promise;
      await vi.advanceTimersByTimeAsync(BUDGET - Math.floor(BUDGET / 6));
      await f.finalEntered.promise; await stop;
      expect(f.consumer.getCoalescingSnapshot().coalesced_evidence_pending, "the held summary keeps its owned observation").toBe(1);
      const before = [...f.calls]; f.gate.resolve(); await turn();
      await f.consumer.flushCoalescedFlowSummaries(); await f.consumer.flushIngressDrops();
      expect(f.calls, "consumer settlement cannot start another write or flush").toEqual(before);
      expect(f.consumer.getCoalescingSnapshot().coalesced_evidence_pending).toBe(1);
    } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
  });
  it("the final record persists after a lapsed drain", async () => {
    requireSummary(); const f = await fixture("summary"); vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      let settled = false; const stop = f.stop().then(() => { settled = true; }); await f.entered.promise;
      await vi.advanceTimersByTimeAsync(BUDGET - Math.floor(BUDGET / 6));
      // The sink has completed the final append before the remaining hard-deadline slice advances.
      await turn();
      expect(f.entries.some(entry => entry.operation === "filter_stopped"), "the reserved slice persists the final record after drain expiry").toBe(true);
      await f.finalEntered.promise; await stop;
      expect(f.calls.slice(f.calls.indexOf("filter_stopped"))).toEqual(["filter_stopped", "flush"]);
      expect(settled).toBe(true);
      expect(performance.now()).toBeLessThan(BUDGET);
    } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
  });
  it("a hard expiry before the drains writes no final record and starts no later phase", async () => {
    requireSummary(); const f = await fixture("listener"); vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      const stop = f.stop(); await f.entered.promise;
      const reserve = Math.floor(BUDGET / 6);
      await vi.advanceTimersByTimeAsync(BUDGET - reserve);
      const atCutoff = [...f.calls]; await f.consumer.flushCoalescedFlowSummaries();
      expect(f.calls, "the drain cutoff fences consumer writes while an earlier phase still waits").toEqual(atCutoff);
      await vi.advanceTimersByTimeAsync(reserve + CASTLE_WALL_STOP_TEST_SLACK_MS); await stop;
      expect(f.calls, "hard expiry skips the final record").not.toContain("filter_stopped");
      const before = [...f.calls]; f.gate.resolve(); await turn();
      expect(f.calls, "hard expiry skips every later phase").toEqual(before);
    } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
  });
  it("stop reports pending evidence on a prompt summary failure", async () => {
    requireSummary(); const f = await fixture("summary-reject"); const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      await f.stop();
      const lines = log.mock.calls.map(([line]) => String(line)).filter(line => line.includes("pending_coalesced=1"));
      expect(lines, "prompt summary failure reports pending coalesced evidence once").toHaveLength(1);
      expect(lines[0]).toContain("coalesced_counters_lower_bound=false");
      expect(performance.now()).toBeLessThan(BUDGET);
    } finally { vi.useRealTimers(); await f.cleanup(); }
  });
  it("a publication skipped during stop is carried into the final record", async () => {
    requireSummary(); const f = await fixture("publication");
    try {
      f.prepareHold(); await f.entered.promise;
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      const stop = f.stop(); await turn(); f.gate.resolve(); await stop;
      expect(f.entries.find(entry => entry.operation === "filter_stopped")?.details?.audit_write_degraded_count,
        "the final carry includes the completed publication outcome").toBe(1);
      expect(performance.now()).toBeLessThan(BUDGET);
    } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
  });
  it("the persisted coalesced detail carries exactly the public keys", async () => {
    requireSummary(); vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] }); const f = await fixture();
    try {
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      await vi.advanceTimersByTimeAsync(1000); // One configured heartbeat interval.
      const detail = f.entries.find(entry => entry.operation === "castle_wall_heartbeat")!.details!;
      expect(Object.keys(detail.coalesced_pending as object).sort()).toEqual([
        "keys", "pending_keys", "coalesced_total", "keys_overflowed", "coalesced_evidence_pending", "coalesced_evidence_confirmed", "summary_write_failures",
      ].sort());
      expect(detail.coalesced_counters_lower_bound).toBe(false);
    } finally { await f.cleanup(); }
  });
  it("production composition coalesces, flushes on heartbeat and drains at stop", async () => {
    requireSummary(); vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] }); const f = await fixture();
    try {
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      expect(f.consumer.getStats().decisionsCoalesced, "production consumer enables counted windows").toBe(1);
      await vi.advanceTimersByTimeAsync(1000); // One injected one-second heartbeat.
      expect(f.entries.filter(entry => entry.operation === "castle_wall_flow_decisions_coalesced")).toHaveLength(1);
      expect(f.entries.find(entry => entry.operation === "castle_wall_heartbeat")?.details).toHaveProperty("ingress_loss_pending");
      await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
      await f.stop();
      expect(f.entries.filter(entry => entry.operation === "castle_wall_flow_decisions_coalesced")).toHaveLength(2);
    } finally { await f.cleanup(); }
  });
});

it("early phase completion inside the reserve preserves final persistence", async () => {
  const f = await fixture("listener");
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  const admissionDrain = vi.spyOn(f.consumer, "drainFlowAdmission");
  const summaryDrain = vi.spyOn(f.consumer, "drainCoalescedFlowSummaries");
  const lossDrain = vi.spyOn(f.consumer, "drainIngressDrops");
  try {
    await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
    const pending = f.consumer.getCoalescingSnapshot().coalesced_evidence_pending;
    expect(pending).toBeGreaterThan(0);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
    const cutoff = BUDGET - Math.floor(BUDGET / D);
    let completed = false; const stop = f.stop().then(() => { completed = true; });
    await f.entered.promise;
    await vi.advanceTimersByTimeAsync(cutoff + EPS);
    expect(completed).toBe(false); expect(f.calls).not.toContain("filter_stopped");
    f.gate.resolve(); await f.finalEntered.promise; await stop;
    expect(performance.now()).toBeLessThan(BUDGET);
    expect(admissionDrain).not.toHaveBeenCalled(); expect(summaryDrain).not.toHaveBeenCalled(); expect(lossDrain).not.toHaveBeenCalled();
    expect(f.calls.slice(f.calls.indexOf("filter_stopped"))).toEqual(["filter_stopped", "flush"]);
    expect(f.entries.some(entry => entry.operation === "filter_stopped")).toBe(true);
    expect(f.consumer.getCoalescingSnapshot().coalesced_evidence_pending).toBe(pending);
    const lines = log.mock.calls.map(([line]) => String(line)).filter(line => line.includes("stop budget lapsed"));
    expect(lines).toHaveLength(1);
    const tokens = lines[0]!.split(" ");
    expect(tokens).toContain("cutoff_state=state_STOP_LISTENER");
    expect(tokens).toContain("phase=state_STOP_LISTENER");
    expect(tokens).toContain("lapse=drain_cutoff"); expect(tokens).toContain("hard_state=none");
  } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
});

it("hard expiry during final persistence reports the final phase", async () => {
  for (const held of ["final", "final-flush"]) {
    const f = await fixture(held), drain = deferred(), drainEntered = deferred();
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const summary = vi.spyOn(f.consumer, "drainCoalescedFlowSummaries").mockImplementation(() => { drainEntered.resolve(); return drain.promise; });
    try {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
      let completed = false; const stop = f.stop().then(() => { completed = true; });
      await drainEntered.promise;
      const cutoff = BUDGET - Math.floor(BUDGET / D);
      await vi.advanceTimersByTimeAsync(cutoff); await f.entered.promise;
      expect(completed).toBe(false);
      expect(f.calls).toContain("filter_stopped");
      if (held === "final") expect(f.calls.slice(f.calls.indexOf("filter_stopped"))).toEqual(["filter_stopped"]);
      else expect(f.calls.slice(f.calls.indexOf("filter_stopped"))).toEqual(["filter_stopped", "flush"]);
      await vi.advanceTimersByTimeAsync(BUDGET - cutoff + EPS); await stop;
      const lines = log.mock.calls.map(([line]) => String(line)).filter(line => line.includes("stop budget lapsed"));
      expect(lines).toHaveLength(1);
      const tokens = lines[0]!.split(" ");
      expect(tokens).toContain("phase=state_STOP_FINAL_RECORD");
      expect(tokens).toContain("hard_state=state_STOP_FINAL_RECORD");
      expect(tokens).toContain("cutoff_state=state_STOP_DRAINS"); expect(tokens).toContain("lapse=hard_expiry");
      const before = [...f.calls]; f.gate.resolve(); drain.resolve(); await turn();
      expect(f.calls, "late persistence starts no later phase").toEqual(before);
    } finally { drain.resolve(); f.gate.resolve(); summary.mockRestore(); vi.useRealTimers(); await f.cleanup(); log.mockRestore(); vi.restoreAllMocks(); }
  }
});

it("final persistence inside the reserve completes without a lapse", async () => {
  const f = await fixture("final"); const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
    const stop = f.stop(); await f.entered.promise;
    const cutoff = BUDGET - Math.floor(BUDGET / D);
    await vi.advanceTimersByTimeAsync(cutoff + EPS);
    f.gate.resolve(); await stop;
    expect(performance.now()).toBeLessThan(BUDGET);
    expect(f.calls.slice(f.calls.indexOf("filter_stopped"))).toEqual(["filter_stopped", "flush"]);
    expect(log.mock.calls.filter(([line]) => String(line).includes("stop budget lapsed"))).toHaveLength(0);
  } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
});

it("the final-record reserve cap bounds a long injected stop budget", async () => {
  const productionWindows = 2; // Two windows make the scaled reserve larger than the production cap.
  const budget = productionWindows * CASTLE_WALL_STOP_DEADLINE_MS;
  const f = await fixture("summary", budget); vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await f.consumer.handleFlowDecisionRecorded(flow()); await f.consumer.handleFlowDecisionRecorded(flow());
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
    const stop = f.stop(); await f.entered.promise;
    const cutoff = budget - FLOW_STOP_FINAL_RECORD_RESERVE_MS;
    await vi.advanceTimersByTimeAsync(cutoff - EPS);
    expect(f.calls).not.toContain("filter_stopped");
    await vi.advanceTimersByTimeAsync(EPS); await f.finalEntered.promise; await stop;
    expect(performance.now()).toBe(cutoff);
    expect(f.entries.some(entry => entry.operation === "filter_stopped")).toBe(true);
  } finally { f.gate.resolve(); vi.useRealTimers(); await f.cleanup(); }
});

import { writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { AuditLog as StorageAuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { MacOSFlowIpcListener } from "../../../src/castle-wall/runtime/macos-ipc-listener.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import { ownershipLedger, reactionTurn, SHORT_HOLD_DEADLINE_MS } from "./flow-ownership-ledger.js";
const HELD_SUMMARY_COUNT = 1; // One selected summary supplies the first recovery and summary failure.
const DAEMON_CASE_TIMEOUT_MS = 60_000; // Include serial holds, stop, and joined raw settlement.
const DAEMON_SLACK_MS = 1_000; // Observe stop after the shared stop budget.
const MS_PER_SECOND = 1000;
const FIXTURE_PERIOD_SECONDS = Math.ceil((DAEMON_CASE_TIMEOUT_MS + DAEMON_SLACK_MS) / MS_PER_SECOND);
const DAEMON_SETUP_MS = 2_000; // Bound each startup and entry observation.
const DAEMON_WAVE_MS = 1_000; // Bound each admitted head and continuation.
const DAEMON_CLEANUP_MS = 2_000; // Bound each late settlement join.
const SUMMARY_OPERATION = "castle_wall_flow_decisions_coalesced";
const LOSS_OPERATION = "castle_wall_ingress_discarded";
const SINGLE_OWNER = 1; // One caller and raw entry owner per immutable reservation.
const SERIAL_DEADLINES = 2; // Summary then loss, with no concurrent lock acquisition.

async function storageDaemon(mode: string, holdListener: boolean) {
  const home = await mkdtemp(join(process.env.HOME!, "flow-stop-"));
  const key = ed25519.utils.randomPrivateKey(), storage = new FilesystemStorage(join(home, "state"));
  const audit = new StorageAuditLog(storage, key, { checkpointInterval: 0, integrityMode: "lenient", writeLockHoldDeadlineMs: SHORT_HOLD_DEADLINE_MS });
  const producerPath = join(home, "producer");
  if (mode === "pinned") await writeFile(producerPath, ed25519.getPublicKey(key));
  const ledger = ownershipLedger(audit, storage, { holdMs: SHORT_HOLD_DEADLINE_MS, setupMs: DAEMON_SETUP_MS, slackMs: DAEMON_SLACK_MS, cleanupMs: DAEMON_CLEANUP_MS, operations: [SUMMARY_OPERATION, LOSS_OPERATION] });
  const listenerStopGate = deferred(), listenerEntered = deferred();
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  let consumer!: MacOSFlowEventConsumer;
  const handle = await startMacOSCastleWallDaemon({ fortressPath: home, fortressId: "fixture", masterKey: key, auditLog: audit,
    platform: "darwin", daemonMode: "safe", socketPath: join(home, "fixture.sock"), activeConfigPath: join(home, "active.json"),
    globalPinnedPublicKeyPath: join(home, "pin"), auditProducerPublicKeyPath: producerPath, auditProducerStatePath: null,
    armLeaseHeartbeatIntervalSeconds: FIXTURE_PERIOD_SECONDS, auditHeartbeatIntervalSeconds: FIXTURE_PERIOD_SECONDS,
    resolverLifecycleRefreshIntervalSeconds: FIXTURE_PERIOD_SECONDS, agentEgressProbeIntervalSeconds: FIXTURE_PERIOD_SECONDS,
    emissionLivenessTickSeconds: FIXTURE_PERIOD_SECONDS,
    agentEgressProbe: async () => true, systemResolverProvider: async () => [],
    signerClientInvoke: async (args, data) => ({ code: 0, stderr: "", stdout: Buffer.from(args[0] === "get-pubkey" ? ed25519.getPublicKey(key) : ed25519.sign(data!, key)).toString("base64url") }),
    listenerFactory(options) { consumer = options.consumer; return {
      async start() {}, async stop() { listenerEntered.resolve(); if (holdListener) await listenerStopGate.promise; },
      async broadcastManifestUpdate() { return 0; }, async broadcastDecisionResponse() { return 0; }, recycleConnection() { return false; }, async broadcastArmLease() { return 0; },
    }; },
  });
  await audit.flush(); await ledger.join(); ledger.clean(0);
  const listener = new MacOSFlowIpcListener({ socketPath: join(home, "routing.sock"), consumer });
  const boundary = listener as unknown as { dispatchFrame(state: unknown, body: string): void; telemetryBytes: number };
  const connection = { subscriberId: "producer", registered: false, inbound: new Uint8Array(), telemetryBytes: 0, socket: { write() { return true; }, destroy() {} } };
  const coalescer = (consumer as unknown as { coalescer: import("../../../src/castle-wall/runtime/macos-flow-coalescing.js").FlowCoalescer }).coalescer;
  const classify = vi.spyOn(coalescer, "classify"), cutoff = vi.spyOn(consumer, "lapseStopBudget");
  const admissionDrain = vi.spyOn(consumer, "drainFlowAdmission"), summaryDrain = vi.spyOn(consumer, "drainCoalescedFlowSummaries");
  const pending: Promise<void>[] = [];
  let seq = 0, prior: string | null = null;
  const frame = () => {
    const notification = flow();
    if (mode === "channel") return notification;
    const timestamp = Date.parse(notification.recorded_at);
    const body = canonicalize({ timestamp: notification.recorded_at, layer: "l1", operation: "egress_blocked", identity_id: TOKEN, result: "blocked",
      details: { agent_id: TOKEN, dest_ip: notification.destination.ip, dest_port: notification.destination.port, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
    const result = { ...notification, producer: { event_canonical_json: body, captured_at_unix_ms: timestamp, seq, prior_sha256_hex: prior,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, timestamp, seq), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } };
    seq++; prior = createHash("sha256").update(body).digest("hex"); return result;
  };
  const dispatch = async () => {
    const before = classify.mock.calls.length;
    boundary.dispatchFrame(connection, JSON.stringify({ jsonrpc: "2.0", method: "castle-wall.flow_decision_recorded", params: frame() }));
    await vi.waitFor(() => { expect(classify.mock.calls.length).toBe(before + 1); expect(boundary.telemetryBytes).toBe(0); }, { timeout: DAEMON_WAVE_MS, interval: 1 });
  };
  const retry = async () => { pending.push(consumer.flushCoalescedFlowSummaries(), consumer.flushIngressDrops()); await reactionTurn(); };
  const prepare = async (exclusive: (operations: string[]) => void) => {
    await dispatch(); await dispatch(); expect(consumer.getStats().decisionsCoalesced).toBe(1);
    pending.push(consumer.flushCoalescedFlowSummaries()); await ledger.deadline(SUMMARY_OPERATION, HELD_SUMMARY_COUNT);
    expect(consumer.getCoalescingSnapshot().summary_write_failures).toBe(HELD_SUMMARY_COUNT);
    pending.push(consumer.flushCoalescedFlowSummaries()); await reactionTurn(); exclusive([SUMMARY_OPERATION]);
    consumer.noteIngressDrop("audit_backpressure"); await ledger.deadline(LOSS_OPERATION, SERIAL_DEADLINES);
    await retry(); exclusive([SUMMARY_OPERATION, LOSS_OPERATION]);
    await dispatch(); await dispatch();
    expect(classify).toHaveBeenCalledTimes(4); // Two head/continuation pairs reach classification.
    expect(coalescer.snapshot()).toMatchObject({ keys: 1, records: 2, coalesced_evidence_pending: 2 });
    await retry(); exclusive([SUMMARY_OPERATION, LOSS_OPERATION]);
    expect(ledger.payloads.filter(record => record.operation === "castle_wall_heartbeat").every(record => !record.details?.audit_write_degraded_count)).toBe(true);
  };
  const diagnostics = () => stderr.mock.calls.map(([line]) => String(line)).filter(line => line.includes("stop budget lapsed"));
  return { audit, storage, ledger, consumer, cutoff, admissionDrain, summaryDrain, listenerEntered, listenerStopGate, prepare, retry, diagnostics,
    stop: () => handle.stop(),
    async settle() { listenerStopGate.resolve(); ledger.release(); await Promise.all(pending); await ledger.join(); },
    async cleanup() {
      listenerStopGate.resolve(); ledger.release(); consumer.closeFlowAdmission();
      try { await Promise.all(pending); await handle.stop(); await ledger.join(); }
      finally { ledger.restore(); classify.mockRestore(); cutoff.mockRestore(); admissionDrain.mockRestore(); summaryDrain.mockRestore(); stderr.mockRestore(); }
      await rm(home, { recursive: true, force: true });
    },
  };
}

it.each(["channel", "pinned"])("daemon expiry retains summary and loss attempts through late storage settlement: %s", async mode => {
  const f = await storageDaemon(mode, true);
  const exclusive = (operations: string[]) => {
    for (const operation of operations) {
      const id = f.ledger.selected.get(operation)!;
      expect(f.ledger.activeAttempts.get(id), `${operation} pre-stop active attempts`).toBe(SINGLE_OWNER);
      expect(f.ledger.highAttempts.get(id), `${operation} pre-stop attempt high-water`).toBe(SINGLE_OWNER);
    }
    f.ledger.exclusive(operations);
  };
  try {
    await f.prepare(exclusive);
    const before = f.ledger.payloads.length, pending = f.consumer.getPendingEvidenceSnapshot();
    const flushesBefore = f.ledger.auditCalls("flush"), durableBefore = f.ledger.auditCalls("flushDurable");
    const began = performance.now(); let stopped = false;
    const stop = f.stop().then(() => { stopped = true; });
    expect(f.consumer.getFlowAdmissionSnapshot().closed).toBe(true);
    await f.listenerEntered.promise;
    await vi.waitFor(() => expect(f.cutoff).toHaveBeenCalled(), { timeout: CASTLE_WALL_STOP_DEADLINE_MS + DAEMON_SLACK_MS, interval: 1 });
    await f.retry(); expect(f.ledger.payloads).toHaveLength(before); f.ledger.exclusive();
    await vi.waitFor(() => expect(stopped).toBe(true), { timeout: CASTLE_WALL_STOP_DEADLINE_MS + DAEMON_SLACK_MS, interval: 1 });
    await stop; await reactionTurn();
    const afterStop = { final: f.ledger.payloads.filter(record => record.operation === "filter_stopped").length, drains: f.admissionDrain.mock.calls.length + f.summaryDrain.mock.calls.length };
    expect(afterStop.final, "no final record after hard expiry").toBe(0);
    expect(afterStop.drains, "no later phase after hard expiry").toBe(0);
    expect(f.ledger.auditCalls("flush")).toBe(flushesBefore);
    expect(performance.now() - began).toBeLessThan(CASTLE_WALL_STOP_DEADLINE_MS + DAEMON_SLACK_MS);
    expect(f.diagnostics()).toHaveLength(1);
    const tokens = f.diagnostics()[0]!.split(" ");
    expect(tokens).toContain("phase=state_STOP_LISTENER"); expect(tokens).toContain("lapse=hard_expiry");
    expect(tokens).toContain("cutoff_state=state_STOP_LISTENER"); expect(tokens).toContain("hard_state=state_STOP_LISTENER");
    f.ledger.exclusive();
    expect(f.consumer.getCoalescingSnapshot()).toEqual(pending.coalesced_pending);
    const flushesAtStop = f.ledger.auditCalls("flush");
    await f.settle();
    expect(f.ledger.auditCalls("flush")).toBe(flushesAtStop);
    expect(f.ledger.auditCalls("flushDurable")).toBe(durableBefore);
    expect(f.ledger.payloads).toHaveLength(before); expect(f.diagnostics()).toHaveLength(1);
    expect(f.consumer.getCoalescingSnapshot()).toEqual(pending.coalesced_pending);
    f.ledger.clean(SERIAL_DEADLINES);
    const entries = (await f.storage.list("_audit")).filter(entry => entry.key.startsWith("entry-")).length;
    const checkpoints = (await f.storage.list("_audit_checkpoints")).filter(entry => entry.key.startsWith("audit-checkpoint-")).length;
    const completedHistory = f.ledger.payloads.filter((_, index) => f.ledger.appendEvents[index]?.completed !== undefined);
    onTestFinished(({ task }) => { (task.meta as Record<string, unknown>).flow = { mode, entries, checkpoints, completedHistory, pending, stopMs: performance.now() - began, recoveries: f.ledger.recoveries.length,
      appendEvents: f.ledger.appendEvents, highAttempts: [...f.ledger.highAttempts], highWrites: [...f.ledger.highWrites] }; });
  } finally { await f.cleanup(); }
}, DAEMON_CASE_TIMEOUT_MS);

it.each(["channel", "pinned"])("daemon reserve lands the final record while summary and loss attempts stay detached: %s", async mode => {
  const f = await storageDaemon(mode, false);
  const exclusive = (operations: string[]) => {
    for (const operation of operations) {
      const id = f.ledger.selected.get(operation)!;
      expect(f.ledger.activeAttempts.get(id), `${operation} pre-stop active attempts`).toBe(SINGLE_OWNER);
      expect(f.ledger.highAttempts.get(id), `${operation} pre-stop attempt high-water`).toBe(SINGLE_OWNER);
    }
    f.ledger.exclusive(operations);
  };
  try {
    await f.prepare(exclusive);
    const before = f.ledger.payloads.length, pending = f.consumer.getPendingEvidenceSnapshot();
    const flushesBefore = f.ledger.auditCalls("flush"), durableBefore = f.ledger.auditCalls("flushDurable");
    const began = performance.now(); let stopped = false;
    const stop = f.stop().then(() => { stopped = true; });
    expect(f.consumer.getFlowAdmissionSnapshot().closed).toBe(true);
    await f.listenerEntered.promise;
    await vi.waitFor(() => expect(f.summaryDrain).toHaveBeenCalled(), { timeout: DAEMON_SETUP_MS, interval: 1 });
    await vi.waitFor(() => expect(f.cutoff).toHaveBeenCalled(), { timeout: CASTLE_WALL_STOP_DEADLINE_MS + DAEMON_SLACK_MS, interval: 1 });
    await f.retry(); f.ledger.exclusive();
    await vi.waitFor(() => expect(stopped).toBe(true), { timeout: FLOW_STOP_FINAL_RECORD_RESERVE_MS + DAEMON_SLACK_MS, interval: 1 });
    await stop;
    const elapsed = performance.now() - began;
    expect(elapsed).toBeGreaterThanOrEqual(CASTLE_WALL_STOP_DEADLINE_MS - FLOW_STOP_FINAL_RECORD_RESERVE_MS);
    expect(elapsed).toBeLessThan(CASTLE_WALL_STOP_DEADLINE_MS);
    expect(await f.ledger.completedCalls("flush", flushesBefore)).toBe(1);
    const finalEvent = f.ledger.appendEvents.find(event => event.operation === "filter_stopped")!;
    expect(finalEvent.started).toBeLessThanOrEqual(finalEvent.completed!);
    expect(finalEvent.completed).toBeDefined();
    expect(finalEvent.completed! - began).toBeLessThan(CASTLE_WALL_STOP_DEADLINE_MS);
    const final = f.ledger.payloads.slice(before);
    expect(final).toHaveLength(1); expect(final[0]!.operation).toBe("filter_stopped");
    expect(final[0]!.details?.audit_write_degraded_count).toBe(SERIAL_DEADLINES);
    expect(f.diagnostics()).toHaveLength(1);
    const tokens = f.diagnostics()[0]!.split(" ");
    expect(tokens).toContain("phase=state_STOP_DRAINS"); expect(tokens).toContain("lapse=drain_cutoff");
    expect(tokens).toContain("cutoff_state=state_STOP_DRAINS"); expect(tokens).toContain("hard_state=none");
    f.ledger.exclusive();
    expect(f.consumer.getCoalescingSnapshot()).toEqual(pending.coalesced_pending);
    const flushesAtStop = f.ledger.auditCalls("flush");
    await f.settle();
    expect(f.ledger.auditCalls("flush")).toBe(flushesAtStop);
    expect(f.ledger.auditCalls("flushDurable")).toBe(durableBefore);
    expect(f.ledger.payloads).toHaveLength(before + 1); expect(f.diagnostics()).toHaveLength(1);
    expect(f.consumer.getCoalescingSnapshot()).toEqual(pending.coalesced_pending);
    f.ledger.clean(SERIAL_DEADLINES);
    const entries = (await f.storage.list("_audit")).filter(entry => entry.key.startsWith("entry-")).length;
    const checkpoints = (await f.storage.list("_audit_checkpoints")).filter(entry => entry.key.startsWith("audit-checkpoint-")).length;
    const completedHistory = f.ledger.payloads.filter((_, index) => f.ledger.appendEvents[index]?.completed !== undefined);
    onTestFinished(({ task }) => { (task.meta as Record<string, unknown>).flow = { mode, entries, checkpoints, completedHistory, pending, stopMs: performance.now() - began, recoveries: f.ledger.recoveries.length,
      appendEvents: f.ledger.appendEvents, highAttempts: [...f.ledger.highAttempts], highWrites: [...f.ledger.highWrites] }; });
  } finally { await f.cleanup(); }
}, DAEMON_CASE_TIMEOUT_MS);
