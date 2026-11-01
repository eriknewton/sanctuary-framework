// Stalled audit appends retain a bounded queue and capacity refusals preserve service admission.
import { expect, it, vi } from "vitest";
import { AuditForwarder } from "../../src/hermes-memory-bridge/process-shell.js";
import { HermesAuditBackpressureError, HERMES_AUDIT_WAITING_CAP, HERMES_MAX_CALL_RECORDS } from "../../src/hermes-memory-bridge/constants.js";
import { HermesBridgeCore } from "../../src/hermes-memory-bridge/bridge-core.js";
import { hermesBridgePassageTextDigest } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { parsePublicFrame, type NodeToRelayInput } from "../../src/hermes-memory-bridge/envelopes.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";

it("caps the waiting forwarder under admission waves and repeated recalls without latching", async () => {
  const target = new AuditLog(new MemoryStorage(), new Uint8Array(32).fill(17));
  let release!: () => void;
  const stalled = new Promise<void>(resolve => { release = resolve; });
  const append = vi.spyOn(target, "appendCritical").mockImplementation(() => stalled);
  const forwarder = new AuditForwarder(); forwarder.bind(target);
  const pending: Promise<void>[] = [];
  const writes: NodeToRelayInput[] = [];
  const core = new HermesBridgeCore({ agentId: "fixture-agent", abort: new AbortController(),
    appendAudit: record => { const result = forwarder.append(record); pending.push(result); return result; }, writeFrame: frame => writes.push(frame),
    nowMs: () => 0, setTimer: () => ({}), clearTimer() {}, adapter: {
      insertPassage: async input => {
        await core.commitCheck.assertAllowedToCommit({ passageId: "fixture", documentId: "mem.agent.fixture",
          passageTextSha256: hermesBridgePassageTextDigest(input.text), passageTextUtf8: Buffer.from(input.text), getFrameUtf8Bytes: 1 });
        throw new Error("a stalled admission must never permit a write");
      }, getPassage: async () => null,
      searchPassages: async () => [], recallPassages: async budget => budget.result(),
    } });
  const call = (request_id: string, name: string, args: unknown) => {
    const publicBytes = Buffer.from(JSON.stringify({ type: "tools_call", request_id, name, arguments: args }));
    core.relayFrame({ kind: "frame", connectionId: "c1", publicBytes, publicFrame: parsePublicFrame(publicBytes) });
  };
  const settle = async (condition: () => boolean) => {
    for (let turn = 0; turn < 100 && !condition(); turn++) await new Promise<void>(resolve => queueMicrotask(resolve));
    expect(condition()).toBe(true);
  };
  try {
    core.relayFrame({ kind: "accepted", connectionId: "c1" });
    // Two cancelled admissions per call-record wave, plus the active and process-row reserves, fill the queue.
    const admissions = HERMES_MAX_CALL_RECORDS * 2 + 2;
    for (let n = 0; n < admissions; n++) {
      call(`insert-${n}`, "memory_insert", { text: "bounded memory", taint: "user_content" });
      const probe = writes.filter(frame => frame.type === "probe").at(-1);
      expect(probe?.type).toBe("probe");
      if (probe?.type === "probe") core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe.nonce });
      await settle(() => pending.length === n + 1);
      const publicBytes = Buffer.from(JSON.stringify({ type: "cancel", mcp_request_id: `insert-${n}` }));
      core.relayFrame({ kind: "frame", connectionId: "c1", publicBytes, publicFrame: parsePublicFrame(publicBytes) });
      await settle(() => core.snapshot().slot === undefined);
      expect(core.snapshot().ledger.latched).toBe(false);
    }
    expect(() => forwarder.append({ kind: "insert_admitted" })).toThrow(HermesAuditBackpressureError);
    const queue = forwarder as unknown as { waiting: unknown[] };
    expect(queue.waiting).toHaveLength(HERMES_AUDIT_WAITING_CAP);
    writes.length = 0;
    for (let n = 0; n < HERMES_MAX_CALL_RECORDS; n++) {
      const publicBytes = Buffer.from(JSON.stringify({ type: "tools_call", request_id: `recall-${n}`, name: "memory_recall", arguments: { query: "the" } }));
      core.relayFrame({ kind: "frame", connectionId: "c1", publicBytes, publicFrame: parsePublicFrame(publicBytes) });
      await new Promise<void>(resolve => queueMicrotask(resolve));
      expect(queue.waiting.length).toBeLessThanOrEqual(HERMES_AUDIT_WAITING_CAP);
      expect(core.snapshot().ledger.latched).toBe(false);
    }
    expect(writes).toHaveLength(HERMES_MAX_CALL_RECORDS);
    for (const frame of writes) {
      expect(frame.type).toBe("response");
      if (frame.type === "response") {
        const payload = JSON.parse(Buffer.from(frame.publicPayloadBytes).toString());
        expect(payload.type).toBe("result");
        expect(JSON.parse(payload.payload.content[0].text).outcome).toBe("unavailable");
      }
    }
  } finally {
    core.relayEof(); release(); await Promise.all(pending); append.mockRestore();
  }
});
