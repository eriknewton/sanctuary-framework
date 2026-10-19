/** Gate callbacks can correlate a request with its durable decision without changing legacy payloads. */
import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const KEY_BYTES = 32; // 256-bit in-memory audit encryption key.
const response = (decision: "approve" | "deny", decided_by: ApprovalResponse["decided_by"]): ApprovalResponse => ({
  decision, decided_by, decided_at: new Date().toISOString(),
});
function harness(callback: (request: ApprovalRequest) => Promise<ApprovalResponse>) {
  const storage = new MemoryStorage();
  const key = randomBytes(KEY_BYTES);
  const audit = new AuditLog(storage, key);
  const gate = new ApprovalGate(DEFAULT_POLICY, new BaselineTracker(storage, key), new CallbackApprovalChannel(callback), audit);
  return { gate, audit };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("approval audit correlation", () => {
  it.each([
    ["approve", "human"], ["deny", "human"], ["deny", "timeout"],
  ] as const)("binds callback, result and durable audit for %s by %s", async (decision, by) => {
    let callbackId: string | undefined;
    const answer = response(decision, by);
    const { gate, audit } = harness(async (request) => {
      callbackId = request.approval_audit_id;
      return answer;
    });
    const result = await gate.evaluate("state_export", {});
    expect(callbackId).toMatch(/^gate-approval-[0-9a-f]{32}$/u); // 16 random bytes encoded as hex.
    expect(result).toMatchObject({ allowed: decision === "approve", tier: 1, approval_required: true, approval_response: answer, approval_audit_id: callbackId });
    const { entries } = await audit.query({ operation_type: `gate_${decision}:state_export` });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.details?.approval_audit_id).toBe(callbackId);
  });

  it("retains the same callback identifier on channel failure and denial audit", async () => {
    let callbackId: string | undefined;
    const { gate, audit } = harness(async (request) => {
      callbackId = request.approval_audit_id;
      throw new Error("fixture channel failure");
    });
    const result = await gate.evaluate("state_export", {});
    expect(callbackId).toBeTypeOf("string");
    expect(result).toMatchObject({ allowed: false, approval_audit_id: callbackId, approval_response: { decided_by: "channel_failure" } });
    const { entries } = await audit.query({ operation_type: "gate_deny:state_export" });
    expect(entries[0]!.details?.approval_audit_id).toBe(callbackId);
  });

  it("exposes correlation before callback settlement without claiming audit durability", async () => {
    const entered = deferred<ApprovalRequest>();
    const decision = deferred<ApprovalResponse>();
    const auditEntered = deferred<void>();
    const auditRelease = deferred<void>();
    const { gate, audit } = harness((request) => { entered.resolve(request); return decision.promise; });
    const original = audit.appendCritical.bind(audit);
    vi.spyOn(audit, "appendCritical").mockImplementation(async (...args) => {
      auditEntered.resolve();
      await auditRelease.promise;
      return original(...args);
    });
    let settled = false;
    const resultPromise = gate.evaluate("state_export", {}).then((result) => { settled = true; return result; });
    const request = await entered.promise;
    // Always settle parked work, including when a pre-change assertion would fail.
    decision.resolve(response("approve", "human"));
    await auditEntered.promise;
    const wasSettled = settled;
    auditRelease.resolve();
    const result = await resultPromise;
    expect(request.approval_audit_id).toBeTypeOf("string");
    expect(wasSettled).toBe(false);
    expect(result.approval_audit_id).toBe(request.approval_audit_id);
  });

  it("fails closed on audit failure even after exposing a callback identifier", async () => {
    let callbackId: string | undefined;
    const { gate, audit } = harness(async (request) => {
      callbackId = request.approval_audit_id;
      return response("approve", "human");
    });
    vi.spyOn(audit, "appendCritical").mockRejectedValue(new Error("fixture audit failure"));
    await expect(gate.evaluate("state_export", {})).rejects.toThrow("fixture audit failure");
    expect(callbackId).toBeTypeOf("string");
  });

  it("uses distinct request-local identifiers for concurrent identical arguments", async () => {
    const requests: ApprovalRequest[] = [];
    const answers = [deferred<ApprovalResponse>(), deferred<ApprovalResponse>()];
    const bothEntered = deferred<void>();
    const { gate, audit } = harness((request) => {
      const answer = answers[requests.length]!;
      requests.push(request);
      if (requests.length === answers.length) bothEntered.resolve();
      return answer.promise;
    });
    const runs = answers.map(() => gate.evaluate("state_export", {}));
    await bothEntered.promise;
    // Reverse completion proves binding is per request, not a latest-request field.
    answers[1]!.resolve(response("deny", "human"));
    answers[0]!.resolve(response("approve", "human"));
    const results = await Promise.all(runs);
    expect(requests.every((request) => typeof request.approval_audit_id === "string")).toBe(true);
    expect(new Set(requests.map((request) => request.approval_audit_id)).size).toBe(answers.length);
    expect(results.map((result) => result.approval_audit_id)).toEqual(requests.map((request) => request.approval_audit_id));
    const { entries } = await audit.query({});
    expect(new Set(entries.map((entry) => entry.details?.approval_audit_id))).toEqual(new Set(requests.map((request) => request.approval_audit_id)));
  });

  it("preserves existing caller serialization and outcomes while making correlation immutable", async () => {
    const requests: ApprovalRequest[] = [];
    const answer = response("approve", "human");
    const { gate } = harness(async (request) => { requests.push(request); return answer; });
    const approved = await gate.evaluate("state_export", {});
    const read = await gate.evaluate("memory_get", { passage_id: "fixture" });
    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    expect(request.approval_audit_id).toBe(approved.approval_audit_id);
    expect(request.approval_audit_id).toBeTypeOf("string");
    const legacy = {
      operation: request.operation, tier: request.tier, reason: request.reason,
      context: request.context, timestamp: request.timestamp, args_binding: request.args_binding,
    };
    expect(JSON.stringify(request)).toBe(JSON.stringify(legacy));
    expect({ ...request }).toEqual(legacy);
    expect(Object.getOwnPropertyDescriptor(request, "approval_audit_id"))
      .toMatchObject({ writable: false, enumerable: false, configurable: false });
    expect(Reflect.set(request, "approval_audit_id", "caller-chosen")).toBe(false);
    expect(approved).toMatchObject({ allowed: true, tier: 1, approval_required: true, approval_response: answer });
    expect(read).toMatchObject({ allowed: true, tier: 3, approval_required: false });
    expect(read).not.toHaveProperty("approval_audit_id");
  });
});
