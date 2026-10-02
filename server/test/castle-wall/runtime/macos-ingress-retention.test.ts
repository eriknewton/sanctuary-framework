/** Bounded daemon ingestion under slow persistence, reconnects and expired approvals. */
import { describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import type { Socket } from "node:net";
import type { AuditLog } from "../../../src/operational/audit-log.js";
import { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import { MacOSFlowIpcListener } from "../../../src/castle-wall/runtime/macos-ipc-listener.js";
import { startMacOSCastleWallDaemon, type MacOSCastleWallListenerOptions } from "../../../src/castle-wall/runtime/macos-daemon.js";
import type { AuditSink } from "../../../src/castle-wall/runtime/audit-consumer.js";

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));
const SUBJECT = Buffer.from(new Uint32Array([0, 501, 501, 501, 501, 123, 1, 1]).buffer).toString("hex");
const FLOW = JSON.stringify({ jsonrpc: "2.0", method: "castle-wall.flow_decision_recorded", params: {
  type: "flow_decision_recorded", decision: "drop", agent: { id: SUBJECT, template: "test" },
  destination: { ip: "192.0.2.1", port: 443, protocol: "tcp" }, recorded_at: "2026-10-01T00:00:00Z",
} });
const OTHER_TELEMETRY = [
  { type: "flow_pending_approval", request_id: "invalid", surface: "egress" },
  { type: "audit_emit", event: { layer: "l1", event_type: "invalid", fortress_id: "test" } },
].map((params) => JSON.stringify({ jsonrpc: "2.0", method: `castle-wall.${params.type}`, params }));
function state(subscriberId: string) {
  return { subscriberId, registered: false, inbound: new Uint8Array(), socket: { write: () => true, destroy() {} } as unknown as Socket };
}
function fixture(sink: AuditSink) {
  const consumer = new MacOSFlowEventConsumer({
    auditSink: sink, fortressId: "retention-test", defaultApprovalTimeoutSeconds: 30,
    approvalQueue: { async enqueue() {} },
    manifestProvider: { currentSnapshot() { throw new Error("unused snapshot"); } },
  });
  const listener = new MacOSFlowIpcListener({ socketPath: "unused.sock", consumer });
  // Exercise the real dispatch boundary without kernel buffering hiding admissions.
  const dispatch = (connection: ReturnType<typeof state>, body = FLOW) =>
    (listener as unknown as { dispatchFrame(s: ReturnType<typeof state>, body: string): void }).dispatchFrame(connection, body);
  return { consumer, listener, dispatch };
}

describe("macOS ingress retention", () => {
  it("bounds two repeated admission waves across disconnected origins until late writes settle", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let admitted = 0, discarded = 0;
    const sink: AuditSink = {
      async append(_layer, operation, _id, details) {
        if (operation !== "castle_wall_ingress_discarded") admitted++;
        await gate;
        if (operation === "castle_wall_ingress_discarded") discarded += (details?.counts as Record<string, number>).audit_backpressure!;
      },
      async flush() {},
    };
    const f = fixture(sink);
    // 10,000 frames exceed the eight-MiB budget even at its minimum task charge.
    const events = 10_000;
    try {
      const first = state("first");
      for (let i = 0; i < events / 2; i++) f.dispatch(first);
      expect(admitted).toBeGreaterThan(0);
      expect(admitted).toBeLessThanOrEqual(256); // one MiB / four KiB minimum charge
      for (let i = events / 2; i < events; i++) {
        const next = state(`reconnect-${i}`);
        f.dispatch(next, OTHER_TELEMETRY[i % OTHER_TELEMETRY.length]);
        f.consumer.unregisterSubscriber(next.subscriberId);
      }
      const beforeLateCompletion = admitted;
      expect(beforeLateCompletion).toBeLessThanOrEqual(2048); // eight MiB / four KiB
      await turn();
      for (let i = 0; i < events; i++) f.dispatch(state(`late-${i}`));
      expect(admitted).toBe(beforeLateCompletion);
      release();
      await turn(); await turn();
      await f.consumer.flushIngressDrops();
      expect(admitted + discarded).toBe(events * 2);
      f.dispatch(first);
      await turn();
      expect(admitted).toBe(beforeLateCompletion + 1);
    } finally { release(); await turn(); stderr.mockRestore(); }
  });

  it("accounts for payload size and retries a failed discard audit without multiplying writes", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
    let reject!: (e: Error) => void;
    const gate = new Promise<void>((_resolve, rejectGate) => { reject = rejectGate; });
    void gate.catch(() => {}); // cleanup also consumes the gate on the fail-before path
    let writes = 0, discarded = 0;
    const f = fixture({
      async append(_layer, operation, _id, details) {
        expect(operation).toBe("castle_wall_ingress_discarded");
        writes++;
        if (writes === 1) await gate;
        discarded += (details?.counts as Record<string, number>).audit_backpressure!;
      },
      async flush() {},
    });
    // A valid JSON flow smaller than the wire frame limit, but larger than
    // one connection's retained-memory allowance after decoding.
    const large = FLOW.replace('"test"', JSON.stringify("x".repeat(256 * 1024)));
    try {
      for (let i = 0; i < 100; i++) f.dispatch(state("large"), large);
      await turn();
      expect(writes).toBe(1);
      reject(new Error("synthetic store failure"));
      await turn();
      expect(writes).toBe(1);
      await f.consumer.flushIngressDrops();
      expect(discarded).toBe(100);
      expect(writes).toBe(2);
    } finally { reject(new Error("cleanup")); await turn(); stderr.mockRestore(); }
  });

  it("bounds the production approval queue, rejects oversized IDs and expires without renewal", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
    const home = await mkdtemp(join(tmpdir(), "cw-retention-"));
    vi.stubEnv("HOME", home);
    let clock = Date.now();
    let options!: MacOSCastleWallListenerOptions;
    let handle: Awaited<ReturnType<typeof startMacOSCastleWallDaemon>> | undefined;
    let discarded = 0;
    const audit = {
      async append(_layer: string, operation: string, _id: string, details?: Record<string, unknown>) {
        if (operation === "castle_wall_ingress_discarded") discarded += Object.values(details!.counts as Record<string, number>).reduce((a, b) => a + b, 0);
      },
      async flush() {}, onWriteLockRecovery() {},
    } as unknown as AuditLog;
    const key = ed25519.utils.randomPrivateKey();
    try {
      handle = await startMacOSCastleWallDaemon({
        fortressPath: home, fortressId: "retention-test", masterKey: key, auditLog: audit,
        platform: "darwin", daemonMode: "safe", now: () => clock,
        socketPath: join(home, "castle.sock"), activeConfigPath: join(home, "active.json"),
        globalPinnedPublicKeyPath: join(home, "pin"), auditProducerPublicKeyPath: join(home, "producer"), auditProducerStatePath: null,
        systemResolverProvider: async () => [], agentEgressProbe: async () => true,
        signerClientInvoke: async (args, data) => ({ code: 0, stderr: "", stdout: Buffer.from(args[0] === "get-pubkey" ? ed25519.getPublicKey(key) : ed25519.sign(data!, key)).toString("base64url") }),
        listenerFactory(opts) { options = opts; return { async start() {}, async stop() {}, async broadcastManifestUpdate() { return 0; }, async broadcastDecisionResponse() { return 0; }, async broadcastArmLease() { return 0; }, recycleConnection() { return false; } }; },
      });
      const enqueue = (id: string, agent = SUBJECT) => options.consumer.handleFlowPendingApproval({
        type: "flow_pending_approval", request_id: id, surface: "egress", agent: { id: agent, template: "test" },
        destination: { ip: "192.0.2.1", port: 443, protocol: "tcp", host: null, hostname_source: null, opaque: false }, expires_in_seconds: 30,
      });
      const decide = (id: string) => options.adminHandler!.handleDecision({ type: "decision_response", request_id: id, decision: "deny_once" });
      // One subject floods while other subjects retain their admission share.
      for (let i = 0; i < 5000; i++) await enqueue(`request-${i}`);
      expect((await decide("request-4999")).ok).toBe(false);
      expect((await decide("request-0")).ok).toBe(true);
      await enqueue("other", "other-subject");
      expect((await decide("other")).ok).toBe(true);
      for (let i = 0; i < 500; i++) await enqueue(`origin-${i}`, `subject-${i}`);
      let acceptedSubjects = 0;
      for (let i = 0; i < 500; i++) {
        if ((await decide(`origin-${i}`)).ok) acceptedSubjects++;
      }
      expect(acceptedSubjects).toBeGreaterThan(0);
      expect(acceptedSubjects).toBeLessThanOrEqual(128); // 128 KiB / one KiB per entry
      await enqueue("x".repeat(129)); // one character above the ID budget
      expect((await decide("x".repeat(129))).ok).toBe(false);
      clock += 29_000;
      await enqueue("request-1"); // duplicate cannot refresh the original TTL
      clock += 2_000;
      expect((await decide("request-1")).ok).toBe(false);
      await enqueue("fresh");
      expect((await decide("fresh")).ok).toBe(true);
      await options.consumer.flushIngressDrops();
      expect(discarded).toBeGreaterThan(4900);
    } finally {
      try { await handle?.stop(); }
      finally {
        await rm(home, { recursive: true, force: true });
        vi.unstubAllEnvs();
        stderr.mockRestore();
      }
    }
  });
});
