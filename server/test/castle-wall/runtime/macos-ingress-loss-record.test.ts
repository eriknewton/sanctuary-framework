/** Loss records retain delivery counts and pending evidence independently of the audit sink. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
import type { AuditSink } from "../../../src/castle-wall/runtime/audit-consumer.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { establishMaster } from "../../../src/core/master-custody.js";
import { runAuditDump } from "../../../src/cli/castle-wall.js";
import { initializeTestCustody } from "../../helpers/custody-fixture.js";
const NOW = Date.parse("2026-11-04T00:00:00Z");
const TOKEN = Buffer.from(new Uint32Array([0, 501, 501, 501, 501, 123, 1, 1]).buffer).toString("hex"); // Ordinary fixture principal.
const key = ed25519.utils.randomPrivateKey(), pin = Buffer.from(ed25519.getPublicKey(key)).toString("base64url");
function frame(pinned = false) {
  const timestamp = new Date(NOW).toISOString();
  const body = canonicalize({ timestamp, layer: "l1", operation: "egress_blocked", identity_id: TOKEN, result: "blocked", details: { agent_id: TOKEN, dest_ip: "192.0.2.1", dest_port: 443, dest_protocol: "tcp", decision: "drop", seq: 0, prior_sha256_hex: null } });
  return { type: "flow_decision_recorded" as const, decision: "drop" as const, agent: { id: TOKEN, template: "fixture" }, recorded_at: timestamp,
    destination: { ip: "192.0.2.1", port: 443, protocol: "tcp" as const, host: null, hostname_source: null, opaque: false },
    ...(pinned ? { producer: { event_canonical_json: body, captured_at_unix_ms: NOW, seq: 0, prior_sha256_hex: null,
      signature_b64url: Buffer.from(ed25519.sign(producerSigningBytes(body, NOW, 0), key)).toString("base64url"), key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } } : {}),
  };
}
function fixture(sink: AuditSink, pinned = false) {
  return new MacOSFlowEventConsumer({ auditSink: sink, fortressId: "fixture", coalesceLiveFlows: true, now: () => NOW,
    ...(pinned ? { pinnedProducerKeyB64url: pin } : {}), defaultApprovalTimeoutSeconds: 30,
    approvalQueue: { async enqueue() {} }, manifestProvider: { currentSnapshot() { throw new Error("unused"); } },
  });
}
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
function requireSummary(consumer: MacOSFlowEventConsumer) { expect(consumer.flushCoalescedFlowSummaries).toBeTypeOf("function"); }
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
describe("delivery loss accounting", () => {
  it.each(["pinned", "channel"])("a failed %s delivery adds one unconfirmed attempt", async path => {
    const pinned = path === "pinned";
    const consumer = fixture({ append() { throw new Error("fixture sink failure"); }, async flush() {} }, pinned); requireSummary(consumer);
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(consumer.handleFlowDecisionRecorded(frame(pinned))).rejects.toThrow("fixture sink failure"); await turn();
    expect(consumer.getIngressLossSnapshot().counts.audit_persist_failed, "one failed delivery owns one loss count").toBe(1);
    expect(consumer.getStats()).toMatchObject({ received: 1, delivery_unconfirmed_or_discarded: 1, waiting_or_in_flight: 0 });
  });
  it("summary failure reports pending evidence without a terminal loss", async () => {
    const rows: Record<string, unknown>[] = [];
    const consumer = fixture({ append(_l, operation, _id, details) { if (operation === "castle_wall_flow_decisions_coalesced") throw new Error("fixture summary failure"); if (operation === "castle_wall_ingress_discarded") rows.push(details!); }, async flush() {} }); requireSummary(consumer);
    await consumer.handleFlowDecisionRecorded(frame()); await consumer.handleFlowDecisionRecorded(frame()); await consumer.flushCoalescedFlowSummaries();
    expect(consumer.getIngressLossSnapshot()).toMatchObject({ summary_write_failures: 1, coalesced_evidence_pending: 1, counts: { audit_persist_failed: 0 } });
    await consumer.flushIngressDrops();
    expect(rows[0]).toMatchObject({ first_dropped_at: null, last_dropped_at: null, window_ms: 0, summary_write_failures: 1, coalesced_evidence_pending: 1 });
  });
  it("loss reservation carries counts, identity and interval across retries", async () => {
    const rows: Record<string, unknown>[] = []; let fail = true;
    const consumer = fixture({ append(_l, operation, _id, details) { if (operation === "castle_wall_ingress_discarded") { rows.push(structuredClone(details!)); if (fail) throw new Error("fixture failure"); } }, async flush() {} }); requireSummary(consumer);
    vi.spyOn(console, "error").mockImplementation(() => {});
    consumer.noteIngressDrop("audit_backpressure", 3); await consumer.flushIngressDrops(); fail = false; await consumer.flushIngressDrops();
    expect(rows[0], "loss retries preserve complete reservation content").toEqual(rows[1]);
    expect(rows[1]).toMatchObject({ counts: { audit_backpressure: 3 }, batch_seq: 1, first_dropped_at: new Date(NOW).toISOString(), last_dropped_at: new Date(NOW).toISOString(), window_ms: 0 });
    expect(rows[1]?.consumer_instance_id).toBeTypeOf("string");
    expect(consumer.getIngressLossSnapshot().counts.audit_backpressure).toBe(0);
  });
  it.each(["loss record", "coalesced summary"])("audit-dump renders the %s", async kind => {
    const root = await mkdtemp("/tmp/cw-loss-dump-"); vi.stubEnv("HOME", root);
    const passphrase = "isolated-flow-loss-dump";
    class Capture extends Writable { text = ""; override _write(chunk: unknown, _encoding: BufferEncoding, done: () => void) { this.text += String(chunk); done(); } }
    let release: (() => Promise<void>) | undefined;
    try {
      const initial = fixture({ append() {}, async flush() {} }); requireSummary(initial);
      await initializeTestCustody(root, { passphrase });
      const storage = new FilesystemStorage(join(root, "state")); const established = await establishMaster({ storage, passphrase }); release = () => established.masterWriteBarrier?.release() ?? Promise.resolve();
      const audit = new AuditLog(storage, established.masterKey); const consumer = fixture(audit);
      vi.spyOn(console, "error").mockImplementation(() => {});
      if (kind === "loss record") { consumer.noteIngressDrop("audit_backpressure"); await consumer.drainIngressDrops(); }
      else { await consumer.handleFlowDecisionRecorded(frame()); await consumer.handleFlowDecisionRecorded(frame()); await consumer.flushCoalescedFlowSummaries(); }
      await audit.flush(); await release(); release = undefined;
      const out = new Capture();
      expect(await runAuditDump(["--fortress", root], { out, err: new Capture(), env: { HOME: root, SANCTUARY_STORAGE_PATH: root, SANCTUARY_PASSPHRASE: passphrase } })).toBe(0);
      const operation = kind === "loss record" ? "castle_wall_ingress_discarded" : "castle_wall_flow_decisions_coalesced";
      expect(out.text.trim().split("\n").filter(line => line.length > 0).map(line => JSON.parse(line)).some(row => row.operation === operation), "informational operation survives the CLI registry").toBe(true);
    } finally { await release?.(); await rm(root, { recursive: true, force: true }); }
  });
});
