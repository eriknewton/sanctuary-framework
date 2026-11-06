/** Informational root accounting preserves agent evidence, availability and bounded teardown. */
// fail-before-exempt: this change makes the root-flow flood test force a full garbage collection before both heap readings, so the unchanged 64 MiB bound measures retained growth instead of uncollected garbage; it asserts no new product behavior and passes against pre-fix source by construction.
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { ed25519 } from "@noble/curves/ed25519";
import * as flowModule from "../../../src/castle-wall/runtime/macos-flow-events.js";
import { MacOSFlowEventConsumer, type MacOSFlowEventConsumerInput } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import type { AuditSink } from "../../../src/castle-wall/runtime/audit-consumer.js";
import * as producerSignatures from "../../../src/castle-wall/runtime/producer-signature.js";
import { startMacOSCastleWallDaemon, type MacOSCastleWallListenerOptions } from "../../../src/castle-wall/runtime/macos-daemon.js";
import { EmissionLivenessWatchdog, DEFAULT_EMISSION_STALL_GRACE_MS } from "../../../src/castle-wall/audit/emission-liveness.js";
import type { FlowDecisionRecordedNotification } from "../../../src/castle-wall/ipc/messages.js";
import { CASTLE_WALL_STOP_DEADLINE_MS, FLOW_STOP_FINAL_RECORD_RESERVE_MS, CASTLE_WALL_AUDIT_PROVENANCE_KEY, CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { establishMaster } from "../../../src/core/master-custody.js";
import { runAuditDump } from "../../../src/cli/castle-wall.js";
import { initializeTestCustody } from "../../helpers/custody-fixture.js";
import { availabilitySnapshot } from "./availability-report-helper.js";

const SUMMARY = "castle_wall_non_agent_flows_observed";
const FORTRESS = "root-count-test";
const ROOT_REASON = "agent.id must be a non-root macOS audit_token_t hex";
const AGENT_UID = 501; // Fixture ordinary user, distinct from root.
const SETUID_AGENT_UID = 502; // A second ordinary user whose binary has effective root.
const APPROVAL_SECONDS = 30; // Existing default, unused for recorded flows.
const WRITE_DEADLINE_MS = 1_000; // Fault deadline with time for healthy startup, receipt and cleanup writes on a loaded runner.
const STOP_SLACK_MS = 1; // One fake-clock millisecond beyond the global stop deadline.
const HEARTBEAT_MS = 45_000; // Shipped default audit heartbeat cadence.
const FLOOD_FRAMES = 100_000; // Required adversarial workload.
const FLOOD_TIMEOUT_MS = 15 * 60_000; // Fifteen minutes allows strict verification on slow CI CPUs.
const HEAP_BOUND_BYTES = 64 * 1024 * 1024; // 64 MiB bounds retained heap growth across the flood, read after a full collection.
// Without a collection, heapUsed also counts garbage the next GC frees, and that share grows with runner slowness.
setFlagsFromString("--expose-gc");
const collectGarbage = runInNewContext("gc") as () => void;
const SIGNING_SEED = ed25519.utils.randomPrivateKey(); // Fixture-only signing seed, never persisted.
const PIN = Buffer.from(ed25519.getPublicKey(SIGNING_SEED)).toString("base64url");
const COUNTER_KEYS = ["root_verified_total", "root_unverified_total", "root_allow_total", "root_drop_total", "summaries_written", "summaries_skipped_in_flight", "summaries_failed"].sort();
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.useRealTimers(); });

function token(ruid: number, euid = ruid): string {
  // audit_token_t has eight little-endian uint32 words; RUID is word three.
  const words = [0, euid, ruid, ruid, ruid, 123, 1, 1]; // pid 123, session/version 1 are fixture identities.
  const bytes = Buffer.alloc(words.length * Uint32Array.BYTES_PER_ELEMENT);
  words.forEach((word, index) => bytes.writeUInt32LE(word, index * Uint32Array.BYTES_PER_ELEMENT));
  return bytes.toString("hex");
}

function frame(ruid = 0, decision: "allow" | "drop" = "allow", euid = ruid): FlowDecisionRecordedNotification {
  return {
    type: "flow_decision_recorded", decision, recorded_at: new Date().toISOString(),
    agent: { id: token(ruid, euid), template: "fixture" }, matched_rule_id: null,
    destination: { ip: "192.0.2.1", port: 443, protocol: "tcp", host: null, hostname_source: null, opaque: false }, // TEST-NET HTTPS endpoint.
  };
}

function signed(notification = frame(), seq = 0, enforcement?: ReturnType<typeof availabilitySnapshot>): FlowDecisionRecordedNotification {
  const prior = seq === 0 ? null : "ab".repeat(32); // 32-byte SHA-256 fixture for an unconsumed predecessor.
  const details = {
    agent_id: notification.agent.id, agent_template: notification.agent.template,
    dest_ip: notification.destination.ip, dest_port: notification.destination.port,
    dest_protocol: notification.destination.protocol, decision: notification.decision,
    prior_sha256_hex: prior, rule_id: notification.matched_rule_id ?? null, seq,
    source: "macos_extension", ...(enforcement ? { enforcement } : {}),
  };
  const eventCanonicalJson = canonicalize({
    timestamp: notification.recorded_at, layer: "l1",
    operation: notification.decision === "allow" ? "egress_approved" : "egress_blocked",
    identity_id: notification.agent.id, result: notification.decision === "allow" ? "success" : "blocked", details,
  });
  const captured = Date.parse(notification.recorded_at);
  return { ...notification, ...(enforcement ? { enforcement } : {}), producer: {
    event_canonical_json: eventCanonicalJson, captured_at_unix_ms: captured, seq, prior_sha256_hex: prior,
    key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(eventCanonicalJson, captured, seq), SIGNING_SEED)).toString("base64url"),
  } };
}

function fixture(overrides: Partial<MacOSFlowEventConsumerInput> = {}) {
  const append = vi.fn<AuditSink["append"]>();
  const flush = vi.fn(async () => {});
  const consumer = new MacOSFlowEventConsumer({
    fortressId: FORTRESS, auditSink: { append, flush }, defaultApprovalTimeoutSeconds: APPROVAL_SECONDS,
    approvalQueue: { async enqueue() {} },
    manifestProvider: { currentSnapshot() { throw new Error("unused snapshot"); } },
    ...overrides,
  });
  return { consumer, append, flush };
}

function requireSummary(consumer: MacOSFlowEventConsumer) {
  // Base-tree absence is an assertion failure, never an import or collection error.
  expect(consumer.flushNonAgentFlowSummary).toBeTypeOf("function");
}

describe("root flow accounting", () => {
  it.each([
    ["subject", () => ({ ...frame(), producer: signed(frame(AGENT_UID, "drop")).producer })],
    ["decision", () => ({ ...frame(), producer: signed(frame(0, "drop")).producer })],
    ["seq", () => signedBodyOverride({ details: { seq: 1 } })], // Envelope seq stays zero.
    ["operation", () => signedBodyOverride({ operation: "egress_blocked" })],
    ["layer", () => signedBodyOverride({ layer: "other" })],
    ["details", () => signedBodyOverride({ details: null })],
  ] as const)("R1 signed %s must bind before root counting", async (_name, makeFrame) => {
    const f = fixture({ pinnedProducerKeyB64url: PIN });
    const notification = makeFrame();
    await f.consumer.handleFlowDecisionRecorded(notification);
    expect(f.append).toHaveBeenCalledExactlyOnceWith("l1", "flow_decision_rejected", notification.agent.id, { reason: ROOT_REASON }, "failure");
    expect(f.flush).toHaveBeenCalledOnce();
    expect(f.consumer.getStats().nonAgentRootFlowsCounted).toBe(0);
    expect(f.consumer.getNonAgentFlowCounters()).toMatchObject({ root_verified_total: 0, root_allow_total: 0, root_drop_total: 0 });
  });

  it("R1 counts the signed decision after binding the frame", async () => {
    const f = fixture({ pinnedProducerKeyB64url: PIN });
    const notification = signed();
    const verify = producerSignatures.verifyProducerSignature;
    vi.spyOn(producerSignatures, "verifyProducerSignature").mockImplementationOnce((...args) => {
      const result = verify(...args);
      // An in-process accessor changes only the carrier after its binding read;
      // the signed decision must remain the source of the informational split.
      Object.defineProperty(notification, "decision", { configurable: true, get() {
        Object.defineProperty(notification, "decision", { value: "drop", configurable: true });
        return "allow";
      } });
      return result;
    });
    await f.consumer.handleFlowDecisionRecorded(notification);
    expect(f.append).not.toHaveBeenCalled();
    expect(f.consumer.getNonAgentFlowCounters()).toMatchObject({ root_verified_total: 1, root_allow_total: 1, root_drop_total: 0 });
  });

  it("R2 pinned root without producer is rejected once and never counted", async () => {
    const f = fixture({ pinnedProducerKeyB64url: PIN });
    const notification = frame();
    await f.consumer.handleFlowDecisionRecorded(notification);
    expect(f.append).toHaveBeenCalledExactlyOnceWith("l1", "flow_decision_rejected", notification.agent.id, { reason: ROOT_REASON }, "failure");
    expect(f.flush).toHaveBeenCalledOnce();
    expect(f.consumer.getStats().nonAgentRootFlowsCounted).toBe(0);
    expect(f.consumer.getNonAgentFlowCounters()).toMatchObject({ root_verified_total: 0, root_unverified_total: 0 });
  });

  it("T1 classification preserves every legacy rejection and RUID attribution", async () => {
    const f = fixture({ pinnedProducerKeyB64url: PIN });
    const root = signed();
    await f.consumer.handleFlowDecisionRecorded(root);
    expect(f.append).not.toHaveBeenCalled();
    expect(f.consumer.getStats().nonAgentRootFlowsCounted).toBe(1);
    expect(flowModule.validateFlowDecisionRecorded(root)).toBe(ROOT_REASON);
    expect(flowModule.validateFlowDecisionRecordedTyped(root).code).toBe("root");
    const bad = signed();
    bad.producer!.signature_b64url = "bad";
    const cases: Array<[string, unknown, string]> = [
      ["bad signature", bad, ROOT_REASON],
      ["type", { ...root, type: "other" }, "unexpected message type: other"],
      ["decision", { ...root, decision: "other" }, "decision must be allow or drop (got other)"],
      ["missing agent", { ...root, agent: null }, "missing agent.id"],
      ["missing id", { ...root, agent: { template: "fixture" } }, "missing agent.id"],
      ["empty id", { ...root, agent: { id: "" } }, "missing agent.id"],
      ["non-string id", { ...root, agent: { id: 0 } }, "missing agent.id"],
      ["destination", { ...root, destination: null }, ROOT_REASON],
      ["destination ip", { ...root, destination: { ip: null } }, ROOT_REASON],
      ["recorded_at missing", { ...root, recorded_at: undefined }, ROOT_REASON],
      ["recorded_at empty", { ...root, recorded_at: "" }, ROOT_REASON],
      ["matched_rule_id", { ...root, matched_rule_id: false }, ROOT_REASON],
      ["malformed token", { ...root, agent: { ...root.agent, id: "invalid" } }, ROOT_REASON],
    ];
    for (const [name, value, reason] of cases) {
      const notification = value as FlowDecisionRecordedNotification;
      f.append.mockClear(); f.flush.mockClear();
      expect(flowModule.validateFlowDecisionRecorded(notification), name).toBe(reason);
      await f.consumer.handleFlowDecisionRecorded(notification);
      expect(f.append, name).toHaveBeenCalledExactlyOnceWith("l1", "flow_decision_rejected", notification.agent?.id ?? "unknown", { reason }, "failure");
      expect(f.flush, name).toHaveBeenCalledOnce();
    }
    for (const [ruid, euid] of [[AGENT_UID, AGENT_UID], [SETUID_AGENT_UID, 0]]) {
      const agent = fixture();
      const notification = frame(ruid, "drop", euid);
      await agent.consumer.handleFlowDecisionRecorded(notification);
      expect(flowModule.validateFlowDecisionRecorded(notification)).toBeNull();
      expect(flowModule.validateFlowDecisionRecordedTyped(notification).code).toBe("agent");
      expect(agent.append.mock.calls[0]?.[1]).toBe("egress_blocked");
      expect(agent.consumer.getStats().nonAgentRootFlowsCounted).toBe(0);
    }
    const unpinned = fixture();
    await unpinned.consumer.handleFlowDecisionRecorded(frame());
    expect(unpinned.consumer.getNonAgentFlowCounters()).toMatchObject({ root_verified_total: 0, root_unverified_total: 1 });
  });

  it("T1 availability is processed before counting root traffic", async () => {
    const observed = vi.fn();
    const f = fixture({ pinnedProducerKeyB64url: PIN, onVerifiedAvailabilityReport: observed });
    const notification = signed(frame(), 0, availabilitySnapshot());
    await f.consumer.handleFlowDecisionRecorded(notification, "fixture-connection");
    expect(f.consumer.getStats().nonAgentRootFlowsCounted).toBe(1);
    expect(observed).toHaveBeenCalledOnce();
    expect(f.consumer.getStats().enforcementAvailabilityReportsRecorded).toBe(1);
    expect(f.append).not.toHaveBeenCalled();
  });

  it("T2 arrival does no append flush or emission work", async () => {
    const emissionLiveness = { noteDecision: vi.fn(), noteRejection: vi.fn(), noteEmission: vi.fn() };
    const f = fixture({ pinnedProducerKeyB64url: PIN, emissionLiveness });
    await f.consumer.handleFlowDecisionRecorded(signed());
    await turn();
    expect(f.append).not.toHaveBeenCalled();
    expect(f.flush).not.toHaveBeenCalled();
    expect(emissionLiveness.noteDecision).not.toHaveBeenCalled();
    expect(emissionLiveness.noteRejection).not.toHaveBeenCalled();
    expect(emissionLiveness.noteEmission).not.toHaveBeenCalled();
  });

  it("T2 100000 verified frames retain fixed state and at most one summary per tick", async () => {
    let appends = 0;
    let summaryAppends = 0;
    const f = fixture({ pinnedProducerKeyB64url: PIN, auditSink: {
      append(_layer, operation) { appends++; if (operation === SUMMARY) summaryAppends++; }, async flush() {},
    } });
    const notification = signed();
    await f.consumer.handleFlowDecisionRecorded(notification);
    expect(appends).toBe(0);
    const keysBefore = Object.keys(f.consumer.getNonAgentFlowCounters()).sort();
    collectGarbage();
    const heapBefore = process.memoryUsage().heapUsed;
    for (let count = 1; count < FLOOD_FRAMES; count++) await f.consumer.handleFlowDecisionRecorded(notification);
    collectGarbage();
    const growth = process.memoryUsage().heapUsed - heapBefore;
    expect(appends).toBe(0);
    expect(growth).toBeLessThan(HEAP_BOUND_BYTES);
    expect(Object.keys(f.consumer.getNonAgentFlowCounters()).sort()).toEqual(keysBefore);
    expect(keysBefore).toEqual(COUNTER_KEYS);
    const ticks = 3; // One changed snapshot and two quiet heartbeat opportunities.
    for (let tick = 0; tick < ticks; tick++) await f.consumer.flushNonAgentFlowSummary();
    expect(summaryAppends).toBeLessThanOrEqual(ticks);
    expect(summaryAppends).toBe(1);
    expect(f.consumer.getNonAgentFlowCounters().root_verified_total).toBe(FLOOD_FRAMES);
  }, FLOOD_TIMEOUT_MS);

  it("T3 root-only traffic leaves the emission watchdog idle", async () => {
    let now = Date.now();
    const onStall = vi.fn();
    const watchdog = new EmissionLivenessWatchdog({ now: () => now, onStall, onRecovery() {} });
    const f = fixture({ emissionLiveness: watchdog });
    const flood = 100; // Well above the two-decision watchdog threshold.
    for (let index = 0; index < flood; index++) await f.consumer.handleFlowDecisionRecorded(frame());
    now += DEFAULT_EMISSION_STALL_GRACE_MS * 2; // Two grace windows expose a false divergence.
    watchdog.evaluate();
    expect(watchdog.snapshot().decidedTotal).toBe(0);
    expect(watchdog.snapshot().emittedTotal).toBe(0);
    expect(watchdog.snapshot().rejectedTotal).toBe(0);
    expect(onStall).not.toHaveBeenCalled();
  });

  it("T4 one slot survives overlapping ticks and publishes cumulative totals", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const f = fixture();
    requireSummary(f.consumer);
    f.append.mockImplementationOnce(() => gate);
    try {
      await f.consumer.handleFlowDecisionRecorded(frame());
      const first = f.consumer.flushNonAgentFlowSummary();
      await turn();
      expect(f.append).toHaveBeenCalledOnce();
      await f.consumer.handleFlowDecisionRecorded(frame(0, "drop"));
      const skippedTicks = 3; // Repeat admission while the first slot is occupied.
      for (let tick = 0; tick < skippedTicks; tick++) void f.consumer.flushNonAgentFlowSummary();
      await turn();
      expect(f.append).toHaveBeenCalledOnce();
      expect(f.consumer.getNonAgentFlowCounters().summaries_skipped_in_flight).toBe(skippedTicks);
      release(); await first;
      expect(f.append).toHaveBeenCalledOnce();
      await f.consumer.flushNonAgentFlowSummary();
      expect(f.append).toHaveBeenCalledTimes(2);
      expect(f.append.mock.calls[1]?.[3]).toMatchObject({ root_unverified_total: 2, root_allow_total: 1, root_drop_total: 1, summary_seq: 2 });
      expect(f.consumer.getNonAgentFlowCounters().summaries_written).toBe(2);
      await f.consumer.flushNonAgentFlowSummary();
      expect(f.append).toHaveBeenCalledTimes(2);
      expect(f.consumer.hasUnpersistedNonAgentFlows()).toBe(false);
    } finally { release(); await f.consumer.drainNonAgentFlowSummary(); }
  });

  it("T4 failure counts once without scheduling a retry", async () => {
    const f = fixture();
    requireSummary(f.consumer);
    // The second call would hang if a retry were introduced; it cannot create an infinite microtask loop.
    let release!: () => void;
    const retryGate = new Promise<void>((resolve) => { release = resolve; });
    f.append.mockRejectedValueOnce(new Error("fixture failure")).mockImplementationOnce(() => retryGate);
    try {
      await f.consumer.handleFlowDecisionRecorded(frame());
      await f.consumer.flushNonAgentFlowSummary();
      await turn();
      expect(f.append).toHaveBeenCalledOnce();
      expect(f.consumer.getNonAgentFlowCounters().summaries_failed).toBe(1);
      expect(f.consumer.hasUnpersistedNonAgentFlows()).toBe(true);
      const next = f.consumer.flushNonAgentFlowSummary();
      release(); await next;
      expect(f.append).toHaveBeenCalledTimes(2);
      expect(f.append.mock.calls[1]?.[3]).toMatchObject({ root_unverified_total: 1, summary_seq: 2, summaries_failed: 1 });
      expect(f.consumer.hasUnpersistedNonAgentFlows()).toBe(false);
    } finally { release(); await f.consumer.drainNonAgentFlowSummary(); }
  });

  it("T4 drain waits for its slot and starts at most one final write", async () => {
    const f = fixture();
    requireSummary(f.consumer);
    let releaseFirst!: () => void;
    let releaseFinal!: () => void;
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const finalGate = new Promise<void>((resolve) => { releaseFinal = resolve; });
    f.append.mockImplementationOnce(() => firstGate).mockImplementationOnce(() => finalGate);
    let drain: Promise<void> | undefined;
    try {
      await f.consumer.handleFlowDecisionRecorded(frame());
      void f.consumer.flushNonAgentFlowSummary();
      await turn();
      await f.consumer.handleFlowDecisionRecorded(frame());
      drain = f.consumer.drainNonAgentFlowSummary();
      await turn();
      expect(f.append).toHaveBeenCalledOnce();
      releaseFirst();
      await turn();
      expect(f.append).toHaveBeenCalledTimes(2);
      await f.consumer.handleFlowDecisionRecorded(frame());
      releaseFinal();
      await drain;
      expect(f.append).toHaveBeenCalledTimes(2);
      expect(f.consumer.hasUnpersistedNonAgentFlows()).toBe(true);
      expect(f.append.mock.calls[1]?.[3]).toMatchObject({ root_unverified_total: 2 });
    } finally { releaseFirst(); releaseFinal(); await drain; }
  });

  it("T7 summary contains only cumulative counts and time bounds without provenance", async () => {
    const f = fixture({ pinnedProducerKeyB64url: PIN });
    requireSummary(f.consumer);
    await f.consumer.handleFlowDecisionRecorded(signed());
    await f.consumer.flushNonAgentFlowSummary();
    const [layer, operation, subject, details, result] = f.append.mock.calls[0]!;
    expect([layer, operation, subject, result]).toEqual(["l1", SUMMARY, FORTRESS, "success"]);
    expect(details).not.toHaveProperty(CASTLE_WALL_AUDIT_PROVENANCE_KEY);
    expect(Object.keys(details!).sort()).toEqual([...COUNTER_KEYS, "summary_seq", "counting_started_at", "window_end"].sort());
    expect(new Date(details!.counting_started_at as string).toISOString()).toBe(details!.counting_started_at);
    expect(new Date(details!.window_end as string).toISOString()).toBe(details!.window_end);
    expect(details).toMatchObject({ root_verified_total: 1, root_unverified_total: 0, summary_seq: 1 });
  });
});

function signedBodyOverride(overrides: Record<string, unknown>): FlowDecisionRecordedNotification {
  const notification = signed();
  const producer = notification.producer!;
  const body = JSON.parse(producer.event_canonical_json);
  const details = overrides.details === null ? null : { ...body.details, ...overrides.details as object };
  producer.event_canonical_json = canonicalize({ ...body, ...overrides, details });
  producer.signature_b64url = Buffer.from(ed25519.sign(producerSigningBytes(
    producer.event_canonical_json, producer.captured_at_unix_ms, producer.seq,
  ), SIGNING_SEED)).toString("base64url");
  return notification;
}

async function daemonFixture() {
  const home = await mkdtemp(join(tmpdir(), "cw-root-summary-"));
  vi.stubEnv("HOME", home);
  const storage = new FilesystemStorage(join(home, "state"));
  const audit = new AuditLog(storage, SIGNING_SEED, { checkpointInterval: 0, integrityMode: "lenient", writeLockHoldDeadlineMs: WRITE_DEADLINE_MS });
  await writeFile(join(home, "producer"), ed25519.getPublicKey(SIGNING_SEED));
  let options!: MacOSCastleWallListenerOptions;
  let handle: Awaited<ReturnType<typeof startMacOSCastleWallDaemon>>;
  try {
    handle = await startMacOSCastleWallDaemon({
      fortressPath: home, fortressId: FORTRESS, masterKey: SIGNING_SEED, auditLog: audit,
      platform: "darwin", daemonMode: "safe", socketPath: join(home, "castle.sock"),
      activeConfigPath: join(home, "active.json"), globalPinnedPublicKeyPath: join(home, "pin"),
      auditProducerPublicKeyPath: join(home, "producer"), auditProducerStatePath: null,
      systemResolverProvider: async () => [], agentEgressProbe: async () => true,
      signerClientInvoke: async (args, data) => ({ code: 0, stderr: "", stdout: Buffer.from(args[0] === "get-pubkey" ? ed25519.getPublicKey(SIGNING_SEED) : ed25519.sign(data!, SIGNING_SEED)).toString("base64url") }),
      listenerFactory(opts) {
        options = opts;
        return { async start() {}, async stop() {}, async broadcastManifestUpdate() { return 0; }, async broadcastDecisionResponse() { return 0; }, async broadcastArmLease() { return 0; }, recycleConnection() { return false; } };
      },
    });
  } catch (error) { await rm(home, { recursive: true, force: true }); throw error; }
  let stopping: Promise<void> | undefined;
  const stop = () => stopping ??= handle.stop();
  return { home, storage, audit, consumer: options.consumer, stop, async cleanup() {
    try { await stop(); await audit.flush(); }
    finally { await rm(home, { recursive: true, force: true }); }
  } };
}

it("T5 bounded stop reports pending totals within its global budget", async () => {
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  const f = await daemonFixture();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const append = f.audit.append.bind(f.audit);
  let blocked = false;
  let finalPersisted!: () => void;
  const finalRecord = new Promise<void>(resolve => { finalPersisted = resolve; });
  vi.spyOn(f.audit, "append").mockImplementation(async (...args) => {
    if (args[1] === SUMMARY) { blocked = true; await gate; blocked = false; }
    const result = await append(...args);
    if (args[1] === "filter_stopped") finalPersisted();
    return result;
  });
  let settled = false;
  try {
    await f.consumer.handleFlowDecisionRecorded(signed());
    expect(f.consumer.flushCoalescedFlowSummaries).toBeTypeOf("function");
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
    void f.stop().then(() => { settled = true; });
    while (!blocked) await turn();
    await vi.advanceTimersByTimeAsync(CASTLE_WALL_STOP_DEADLINE_MS - FLOW_STOP_FINAL_RECORD_RESERVE_MS);
    await finalRecord;
    await f.stop();
    expect(settled, "stop settles within the global budget with the summary held").toBe(true);
    vi.useRealTimers();
    expect(blocked).toBe(true);
    const warnings = stderr.mock.calls.map(([line]) => String(line)).filter((line) => line.startsWith("[castle-wall] stop budget lapsed"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('"root_verified_total":1');
    expect((await f.audit.query({ layer: "l1" })).entries.some((entry) => entry.operation === "filter_stopped")).toBe(true);
    await expect(readFile(join(f.home, "active.json"))).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    vi.useRealTimers();
    release();
    if (f.consumer.drainNonAgentFlowSummary) await f.consumer.drainNonAgentFlowSummary();
    await f.cleanup();
  }
});

it("R3 fast summary failure at stop reports unsaved totals once", async () => {
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  const f = await daemonFixture();
  const append = f.audit.append.bind(f.audit);
  vi.spyOn(f.audit, "append").mockImplementation(async (...args) => {
    if (args[1] === SUMMARY) throw new Error("fixture summary failure");
    return append(...args);
  });
  try {
    await f.consumer.handleFlowDecisionRecorded(signed());
    await f.stop();
    expect(f.consumer.getNonAgentFlowCounters().summaries_failed).toBe(1);
    expect(f.consumer.hasUnpersistedNonAgentFlows()).toBe(true);
    const warnings = stderr.mock.calls.map(([line]) => String(line)).filter((line) => line.startsWith("[castle-wall] non-agent flow summary not persisted at stop:"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('"root_verified_total":1');
    expect((await f.audit.query({ layer: "l1" })).entries.some((entry) => entry.operation === "filter_stopped")).toBe(true);
    await expect(readFile(join(f.home, "active.json"))).rejects.toMatchObject({ code: "ENOENT" });
  } finally { await f.cleanup(); }
});

it("T6 real daemon heartbeat writes root summaries and preserves signed subset agent receipts", async () => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  const f = await daemonFixture();
  try {
    await f.consumer.handleFlowDecisionRecorded(signed(frame(), 0));
    await f.consumer.handleFlowDecisionRecorded(signed(frame(AGENT_UID, "drop"), 1));
    await f.consumer.handleFlowDecisionRecorded(signed(frame(0, "drop"), 2));
    // A root observation ahead of the agent stream cannot advance its sequence floor.
    const rootAheadSeq = 100;
    await f.consumer.handleFlowDecisionRecorded(signed(frame(), rootAheadSeq));
    await f.consumer.handleFlowDecisionRecorded(signed(frame(AGENT_UID), 3));
    const before = (await f.audit.query({ layer: "l1" })).entries;
    expect(before.filter((entry) => entry.operation === "flow_decision_rejected")).toHaveLength(0);
    expect(before.filter((entry) => entry.operation === SUMMARY)).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(HEARTBEAT_MS);
    await vi.waitFor(async () => {
      const summaries = (await f.audit.query({ layer: "l1" })).entries.filter((entry) => entry.operation === SUMMARY);
      expect(summaries).toHaveLength(1);
      expect(summaries[0]!.details).toMatchObject({ root_verified_total: 3, root_allow_total: 2, root_drop_total: 1 });
    });
    const entries = (await f.audit.query({ layer: "l1" })).entries;
    const agents = entries.filter((entry) => ["egress_blocked", "egress_allowed"].includes(entry.operation));
    expect(agents).toHaveLength(2);
    expect(agents.map((entry) => entry.details?.seq).sort()).toEqual([1, 3]);
    for (const agent of agents) {
      expect(agent.identity_id).toBe(`${FORTRESS}/uid-${AGENT_UID}`);
      expect(agent.details).toMatchObject({ cw_evidence_basis: "producer_signed", cw_chain_basis: "producer_signed_body" });
    }
    expect(agents.find((entry) => entry.details?.seq === 3)?.details).toHaveProperty("cw_chain_prior_unconsumed", true);
    expect((await f.audit.query({ layer: "l1" })).integrity_findings).toEqual([]);
  } finally { await f.cleanup(); }
});

class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, done: (error?: Error | null) => void): void {
    this.text += String(chunk); done();
  }
}

it("T7 audit-dump lists informational summary records", async () => {
  const home = await mkdtemp(join(tmpdir(), "cw-summary-dump-"));
  vi.stubEnv("HOME", home);
  const passphrase = "isolated-root-summary-dump-fixture";
  let established: Awaited<ReturnType<typeof establishMaster>> | undefined;
  try {
    await initializeTestCustody(home, { passphrase });
    const storage = new FilesystemStorage(join(home, "state"));
    established = await establishMaster({ storage, passphrase });
    const { masterKey } = established;
    const audit = new AuditLog(storage, masterKey);
    const f = fixture({ pinnedProducerKeyB64url: PIN, auditSink: audit });
    await f.consumer.handleFlowDecisionRecorded(signed());
    await f.consumer.flushNonAgentFlowSummary();
    await audit.flush();
    const out = new Capture();
    const err = new Capture();
    const code = await runAuditDump(["--fortress", home], { out, err, env: { SANCTUARY_STORAGE_PATH: home, SANCTUARY_PASSPHRASE: passphrase } });
    expect(code).toBe(0);
    const entries = out.text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    const summaries = entries.filter((entry) => entry.operation === SUMMARY);
    expect(summaries).toHaveLength(1);
    const summary = entries.find((entry) => entry.operation === SUMMARY);
    expect(summary.details).toMatchObject({ root_verified_total: 1, summary_seq: 1 });
    expect(summary.details).not.toHaveProperty(CASTLE_WALL_AUDIT_PROVENANCE_KEY);
  } finally {
    // Release the reader before deleting the directory whose identity scopes it.
    try { await established?.masterWriteBarrier?.release(); }
    finally { established?.masterKey.fill(0); }
    await rm(home, { recursive: true, force: true });
  }
});
