/** Production flow composition flushes counted evidence and completes stop within one budget. */
import { afterEach, describe, expect, it, vi } from "vitest";
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
