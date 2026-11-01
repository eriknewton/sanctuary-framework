// Stalled audit appends retain a bounded queue and capacity refusals preserve service admission.
import { expect, it, vi } from "vitest";
import { AuditForwarder } from "../../src/hermes-memory-bridge/process-shell.js";
import { HermesAuditBackpressureError, HERMES_AUDIT_WAITING_CAP, HERMES_AUDIT_PROCESS_ROWS, HERMES_MAX_CALL_RECORDS } from "../../src/hermes-memory-bridge/constants.js";
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
    completeAuditInsert: id => forwarder.completeInsert(id),
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
    await expect(forwarder.append({ kind: "insert_admitted" })).rejects.toBeInstanceOf(HermesAuditBackpressureError);
    const queue = forwarder as unknown as { waiting: unknown[] };
    expect(queue.waiting).toHaveLength(HERMES_AUDIT_WAITING_CAP - HERMES_AUDIT_PROCESS_ROWS);
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
    release();
    await Promise.allSettled(pending);
    while (forwarder.pending.size > 0) await Promise.allSettled([...forwarder.pending]);
    const recorded = append.mock.calls.map(([row]) => row.details?.kind);
    expect(recorded.filter(kind => kind === "insert_refused")).toHaveLength(recorded.filter(kind => kind === "insert_admitted").length);
  } finally {
    core.relayEof(); release(); await Promise.allSettled(pending);
    while (forwarder.pending.size > 0) await Promise.allSettled([...forwarder.pending]);
    append.mockRestore();
  }
});

// The process latch has reserved space even when cancelled call rows fill their entire share.
it("records the latch row after a stall fills the call share", async () => {
  const target = new AuditLog(new MemoryStorage(), new Uint8Array(32).fill(17));
  let release!: () => void;
  const stalled = new Promise<void>(resolve => { release = resolve; });
  const append = vi.spyOn(target, "appendCritical").mockImplementationOnce(() => stalled).mockResolvedValue(undefined);
  const forwarder = new AuditForwarder(); forwarder.bind(target);
  const rows = [forwarder.append({ kind: "memory_recall" })]; // One handed-off row is outside the waiting cap.
  try {
    for (let n = 0; n < HERMES_AUDIT_WAITING_CAP - HERMES_AUDIT_PROCESS_ROWS; n++) rows.push(forwarder.append({ kind: "memory_recall" }));
    await expect(forwarder.append({ kind: "memory_recall" })).rejects.toBeInstanceOf(HermesAuditBackpressureError);
    rows.push(forwarder.append({ kind: "latch", reason: "audit" }));
    release();
    await Promise.all(rows);
    expect(append.mock.calls.filter(([row]) => row.details?.kind === "latch")).toHaveLength(1);
  } finally { release(); await Promise.allSettled(rows); append.mockRestore(); }
});

// A latch queued first leaves the whole call share available.
it("keeps a queued latch outside the call share", async () => {
  const target = new AuditLog(new MemoryStorage(), new Uint8Array(32).fill(17));
  let release!: () => void;
  const stalled = new Promise<void>(resolve => { release = resolve; });
  const append = vi.spyOn(target, "appendCritical").mockImplementationOnce(() => stalled).mockResolvedValue(undefined);
  const forwarder = new AuditForwarder(); forwarder.bind(target);
  const rows = [forwarder.append({ kind: "memory_recall" }), forwarder.append({ kind: "latch", reason: "audit" })];
  try {
    for (let n = 0; n < HERMES_AUDIT_WAITING_CAP - HERMES_AUDIT_PROCESS_ROWS; n++) rows.push(forwarder.append({ kind: "memory_recall" }));
    await expect(forwarder.append({ kind: "memory_recall" })).rejects.toBeInstanceOf(HermesAuditBackpressureError);
    release(); await Promise.all(rows);
    expect(append).toHaveBeenCalledTimes(HERMES_AUDIT_WAITING_CAP + 1);
  } finally { release(); await Promise.allSettled(rows); append.mockRestore(); }
});

// Confirmed saves and rejected admissions release capacity across repeated admission waves.
it("reuses terminal reserves after confirmed saves and rejected admissions", async () => {
  const target = new AuditLog(new MemoryStorage(), new Uint8Array(32).fill(17));
  const append = vi.spyOn(target, "appendCritical").mockResolvedValue(undefined);
  const forwarder = new AuditForwarder(); forwarder.bind(target);
  try {
    // Two full waiting-cap waves require reuse rather than a lifetime allowance.
    for (let n = 0; n < HERMES_AUDIT_WAITING_CAP * 2; n++) {
      const entryId = `saved-${n}`;
      await forwarder.append({ kind: "insert_admitted", entryId });
      forwarder.completeInsert(entryId);
      append.mockRejectedValueOnce(new Error("admission fixture"));
      await expect(forwarder.append({ kind: "insert_admitted", entryId: `rejected-${n}` })).rejects.toThrow("admission fixture");
    }
    const report = vi.fn();
    forwarder.close(vi.fn(), report);
    expect(report.mock.calls).toEqual([[HERMES_AUDIT_WAITING_CAP * 2, "append_failure"]]);
  } finally { append.mockRestore(); }
});

// Terminal durability failures are counted without exposing record contents.
it("names terminal append failure once at close", async () => {
  const target = new AuditLog(new MemoryStorage(), new Uint8Array(32).fill(17));
  const append = vi.spyOn(target, "appendCritical").mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error("private fixture"));
  const forwarder = new AuditForwarder(); forwarder.bind(target);
  try {
    await forwarder.append({ kind: "insert_admitted", entryId: "insert" });
    await expect(forwarder.append({ kind: "insert_unconfirmed", entryId: "insert" })).rejects.toThrow("private fixture");
    const report = vi.fn();
    forwarder.close(vi.fn(), report); forwarder.close(vi.fn(), report);
    expect(report.mock.calls).toEqual([[1, "append_failure"]]);
  } finally { append.mockRestore(); }
});

// Terminal rows without a usable reserve are refused and counted without retaining their contents.
it.each(["insert_refused", "insert_unconfirmed"] as const)("names %s without a reserved slot once at close", async kind => {
  const target = new AuditLog(new MemoryStorage(), new Uint8Array(32).fill(17));
  const append = vi.spyOn(target, "appendCritical").mockResolvedValue(undefined);
  const forwarder = new AuditForwarder(); forwarder.bind(target);
  try {
    await forwarder.append({ kind: "insert_admitted", entryId: "private fixture" });
    forwarder.completeInsert("private fixture");
    await expect(forwarder.append({ kind, entryId: "private fixture" })).rejects.toBeInstanceOf(HermesAuditBackpressureError);
    expect(append).toHaveBeenCalledTimes(1);
    const report = vi.fn();
    forwarder.close(vi.fn(), report); forwarder.close(vi.fn(), report);
    expect(report.mock.calls).toEqual([[1, "append_failure"]]);
  } finally { append.mockRestore(); }
});

// A rejection after close remains covered by the reservation already reported at shutdown.
it("counts an admission rejected after close only in the shutdown report", async () => {
  const target = new AuditLog(new MemoryStorage(), new Uint8Array(32).fill(17));
  let reject!: (error: Error) => void;
  const stalled = new Promise<void>((_resolve, fail) => { reject = fail; });
  const append = vi.spyOn(target, "appendCritical").mockReturnValue(stalled);
  const forwarder = new AuditForwarder(); forwarder.bind(target);
  const admission = forwarder.append({ kind: "insert_admitted", entryId: "private fixture" });
  const rejected = expect(admission).rejects.toThrow("private fixture");
  try {
    const report = vi.fn();
    expect(forwarder.close(vi.fn(), report)).toBe(1);
    reject(new Error("private fixture"));
    await rejected;
    expect(forwarder.close(vi.fn(), report)).toBe(0);
    expect(report.mock.calls).toEqual([[1, "shutdown_deadline"]]);
  } finally {
    reject(new Error("private fixture")); await Promise.allSettled([admission]); append.mockRestore();
  }
});
