/** Production flow composition flushes counted evidence and completes stop within one budget. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { startMacOSCastleWallDaemon, type MacOSCastleWallListenerOptions } from "../../../src/castle-wall/runtime/macos-daemon.js";
import { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import type { AuditLog } from "../../../src/operational/audit-log.js";
import { CASTLE_WALL_STOP_DEADLINE_MS, CASTLE_WALL_STOP_EXIT_DEADLINE_MS } from "../../../src/castle-wall/constants.js";
import * as custodyFs from "../../../src/storage/custody-fs.js";
import { generateFullAgentPlist } from "../../../src/cli/castle-wall-full-agent.js";
// Must match CASTLE_WALL_STOP_TEST_SLACK_MS in test/cli/castle-wall-stop-backstop.test.ts: one fake-clock millisecond.
const CASTLE_WALL_STOP_TEST_SLACK_MS = 1;
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
async function fixture(held = "none") {
  const home = await mkdtemp("/tmp/cw-stop-budget-"); vi.stubEnv("HOME", home);
  const gate = deferred(), entered = deferred(); const calls: string[] = [];
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
    stopDeadlineMs: BUDGET, auditHeartbeatIntervalSeconds: 1, resolverLifecycleRefreshIntervalSeconds: 2, // Distinct fixture timer periods.
    systemResolverProvider: async () => { if (held === "resolver" && started) { entered.resolve(); await gate.promise; } return []; }, agentEgressProbe: async () => true,
    signerClientInvoke: async (args, data) => ({ code: 0, stderr: "", stdout: Buffer.from(args[0] === "get-pubkey" ? ed25519.getPublicKey(key) : ed25519.sign(data!, key)).toString("base64url") }),
    listenerFactory(opts) { options = opts; return {
      async start() {}, async stop() { calls.push("listener-stop"); if (held === "listener") { entered.resolve(); await gate.promise; } },
      async broadcastManifestUpdate() { return 0; }, async broadcastDecisionResponse() { return 0; }, recycleConnection() { return false; },
      async broadcastArmLease() { if (stopping) { calls.push("standdown"); if (held === "lease") { entered.resolve(); await gate.promise; } } return 0; },
    }; },
  });
  started = true;
  if (held === "cleanup") {
    const read = custodyFs.readFileCustody;
    vi.spyOn(custodyFs, "readFileCustody").mockImplementation(async (...args) => {
      if (stopping && args[0] === join(home, "active.json")) { calls.push("cleanup"); entered.resolve(); await gate.promise; }
      return read(...args);
    });
  }
  return { consumer: options.consumer, calls, entries, entered, gate,
    prepareHold() { if (held === "resolver") intervals.get(2000)!(); if (held === "heartbeat") intervals.get(1000)!(); },
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
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      let settled = false; const stop = f.stop().then(() => { settled = true; });
      await f.entered.promise;
      await vi.advanceTimersByTimeAsync(BUDGET + CASTLE_WALL_STOP_TEST_SLACK_MS);
      expect(settled, "stop completion flag is set within the shared budget").toBe(true);
      expect(log.mock.calls.filter(([line]) => String(line).includes("stop budget lapsed"))).toHaveLength(1);
      expect(f.consumer.getFlowAdmissionSnapshot().closed).toBe(true);
      const phase = ({ resolver: "RESOLVER_WAIT", heartbeat: "HEARTBEAT_IDLE", lease: "LEASE_STANDDOWN", listener: "LISTENER", head: "DRAINS", loss: "DRAINS", summary: "DRAINS", "non-agent": "DRAINS", final: "FINAL_RECORD", "final-flush": "FINAL_RECORD", cleanup: "CLEANUP" } as const)[held];
      const diagnostic = log.mock.calls.map(([line]) => String(line)).find(line => line.includes("stop budget lapsed"))!;
      expect(diagnostic).toContain(`phase=state_STOP_${phase}`);
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
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] }); const stop = f.stop(); await f.entered.promise;
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
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] }); const stop = f.stop();
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
