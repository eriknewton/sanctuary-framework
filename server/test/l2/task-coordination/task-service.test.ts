import { describe, expect, it } from "vitest";

import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { createIdentity } from "../../../src/core/identity.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { StateStore } from "../../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import {
  TASK_STATUSES,
  TaskService,
  TaskStateTransitionError,
  type TaskStatus,
} from "../../../src/l2-operational/task-coordination/index.js";
import { MemoryStorage } from "../../../src/storage/memory.js";

function makeService(fortressId = "fortress-a") {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    "operator",
    identityEncryptionKey,
    "recovery-key",
  );
  const service = new TaskService({
    stateStore,
    auditLog,
    fortressId,
    identityId: storedIdentity.identity_id,
    signingIdentity: storedIdentity,
    identityEncryptionKey,
    enqueueReviewApproval: (task) => `approval-${task.id}`,
    now: () => new Date("2026-05-16T12:00:00.000Z"),
  });
  return { service, stateStore, auditLog, storage, masterKey, storedIdentity };
}

describe("TaskService", () => {
  it("creates, lists, shows, assigns, updates, and cancels tasks", async () => {
    const { service } = makeService();

    const created = await service.create({
      title: "Review handoff",
      description: "Check the ready state",
      creator: "operator",
      assignee: "agent-a",
    });
    await expect(service.get(created.id)).resolves.toMatchObject({
      id: created.id,
      title: "Review handoff",
      status: "pending",
    });

    const assigned = await service.assign(created.id, {
      assignee: "agent-b",
      actor: "operator",
    });
    expect(assigned.assignee).toBe("agent-b");

    const inProgress = await service.updateStatus(created.id, {
      status: "in_progress",
      actor: "agent-b",
    });
    expect(inProgress.status).toBe("in_progress");

    const listed = await service.list({
      status: "in_progress",
      assignee: "agent-b",
    });
    expect(listed.map((task) => task.id)).toEqual([created.id]);

    const cancelled = await service.cancel(created.id, {
      actor: "operator",
      reason: "superseded",
    });
    expect(cancelled.status).toBe("cancelled");
    expect(cancelled.metadata?.cancel_reason).toBe("superseded");
  });

  it("rejects every illegal state-machine transition", async () => {
    const allowed: Record<TaskStatus, TaskStatus[]> = {
      pending: ["in_progress", "blocked", "cancelled"],
      in_progress: ["blocked", "ready_for_review", "completed", "cancelled"],
      blocked: ["in_progress", "cancelled"],
      ready_for_review: ["completed", "in_progress", "cancelled"],
      completed: [],
      cancelled: [],
    };

    for (const from of TASK_STATUSES) {
      for (const to of TASK_STATUSES) {
        if (allowed[from].includes(to)) continue;
        const { service } = makeService(`fortress-${from}-${to}`);
        const task = await service.create({ title: `${from} to ${to}`, creator: "operator" });
        await driveTo(service, task.id, from);
        await expect(
          service.updateStatus(task.id, { status: to, actor: "operator" }),
        ).rejects.toBeInstanceOf(TaskStateTransitionError);
      }
    }
  });

  it("emits critical audit entries for lifecycle transitions", async () => {
    const { service, auditLog } = makeService();
    const task = await service.create({ title: "Audit me", creator: "operator" });
    await service.assign(task.id, { assignee: "agent-a", actor: "operator" });
    await service.updateStatus(task.id, {
      status: "in_progress",
      actor: "agent-a",
    });
    await service.cancel(task.id, { actor: "operator" });

    const audit = await auditLog.query({ layer: "l2", limit: 20 });
    expect(audit.entries.map((entry) => entry.operation)).toEqual([
      "task.create",
      "task.assign",
      "task.update_status",
      "task.cancel",
    ]);
    for (const entry of audit.entries) {
      expect(entry.details?.task_id).toBe(task.id);
      expect(entry.details?.event_type).toBe(entry.operation);
    }
  });

  it("chains ready_for_review into an inbox approval id and audits the chain", async () => {
    const { service, auditLog } = makeService();
    const task = await service.create({ title: "Ready", creator: "operator" });
    await service.updateStatus(task.id, {
      status: "in_progress",
      actor: "operator",
    });

    const ready = await service.updateStatus(task.id, {
      status: "ready_for_review",
      actor: "operator",
    });

    expect(ready.approval_request_id).toBe(`approval-${task.id}`);
    const audit = await auditLog.query({ layer: "l2", limit: 20 });
    expect(audit.entries.map((entry) => entry.operation)).toContain(
      "task.inbox_chain",
    );
  });

  it("isolates task listings by fortress id", async () => {
    const rig = makeService("fortress-a");
    const serviceB = new TaskService({
      stateStore: rig.stateStore,
      auditLog: rig.auditLog,
      fortressId: "fortress-b",
      identityId: rig.storedIdentity.identity_id,
      signingIdentity: rig.storedIdentity,
      identityEncryptionKey: derivePurposeKey(rig.masterKey, "identity-encryption"),
    });

    const a = await rig.service.create({ title: "A", creator: "operator" });
    const b = await serviceB.create({ title: "B", creator: "operator" });

    expect((await rig.service.list()).map((task) => task.id)).toEqual([a.id]);
    expect((await serviceB.list()).map((task) => task.id)).toEqual([b.id]);
    await expect(serviceB.get(a.id)).rejects.toThrow("task not found");
  });
});

async function driveTo(
  service: TaskService,
  taskId: string,
  target: TaskStatus,
): Promise<void> {
  if (target === "pending") return;
  if (target === "in_progress") {
    await service.updateStatus(taskId, { status: "in_progress", actor: "operator" });
    return;
  }
  if (target === "blocked") {
    await service.updateStatus(taskId, { status: "blocked", actor: "operator" });
    return;
  }
  await service.updateStatus(taskId, { status: "in_progress", actor: "operator" });
  if (target === "ready_for_review") {
    await service.updateStatus(taskId, {
      status: "ready_for_review",
      actor: "operator",
    });
    return;
  }
  await service.updateStatus(taskId, { status: target, actor: "operator" });
}
